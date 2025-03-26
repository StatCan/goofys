// Copyright 2019 Ka-Hing Cheung
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	. "github.com/StatCan/goofys/api/common"

	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/corehandlers"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/jacobsa/fuse"
)

type S3Backend struct {
	*s3.S3
	cap Capabilities

	bucket     string
	awsConfig  *aws.Config
	flags      *FlagStorage
	config     *S3Config
	sseType    string
	httpClient *http.Client // do this so we can pass around? init below in NewS3
	aws        bool
	gcs        bool
	v2Signer   bool
}

func NewS3(bucket string, flags *FlagStorage, config *S3Config) (*S3Backend, error) {
	awsConfig, err := config.ToAwsConfig(flags)
	if err != nil {
		return nil, err
	}
	s := &S3Backend{
		bucket:     bucket,
		awsConfig:  awsConfig,
		flags:      flags,
		config:     config,
		httpClient: &http.Client{},
		cap: Capabilities{
			Name: "s3-jose-test",
			// MaxMultipartSize doesnt seem to be respected? or at least it goes to multipart right away.
			MaxMultipartSize:    5 * 1024 * 1024 * 1024,
			NoParallelMultipart: true,
		},
	}

	if flags.DebugS3 {
		awsConfig.LogLevel = aws.LogLevel(aws.LogDebug | aws.LogDebugWithRequestErrors)
	}

	if config.UseKMS {
		//SSE header string for KMS server-side encryption (SSE-KMS)
		s.sseType = s3.ServerSideEncryptionAwsKms
	} else if config.UseSSE {
		//SSE header string for non-KMS server-side encryption (SSE-S3)
		s.sseType = s3.ServerSideEncryptionAes256
	}

	s.newS3()
	return s, nil
}

func (s *S3Backend) Bucket() string {
	return s.bucket
}

func (s *S3Backend) Capabilities() *Capabilities {
	return &s.cap
}

func addAcceptEncoding(req *request.Request) {
	if req.HTTPRequest.Method == "GET" {
		// we need "Accept-Encoding: identity" so that objects
		// with content-encoding won't be automatically
		// deflated, but we don't want to sign it because GCS
		// doesn't like it
		req.HTTPRequest.Header.Set("Accept-Encoding", "identity")
	}
}

func addRequestPayer(req *request.Request) {
	// "Requester Pays" is only applicable to these
	// see https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html
	if req.HTTPRequest.Method == "GET" || req.HTTPRequest.Method == "HEAD" || req.HTTPRequest.Method == "POST" {
		req.HTTPRequest.Header.Set("x-amz-request-payer", "requester")
	}
}

func (s *S3Backend) setV2Signer(handlers *request.Handlers) {
	handlers.Sign.Clear()
	handlers.Sign.PushBack(SignV2)
	handlers.Sign.PushBackNamed(corehandlers.BuildContentLengthHandler)
}

func (s *S3Backend) newS3() {
	s.S3 = s3.New(s.config.Session, s.awsConfig)
	if s.config.RequesterPays {
		s.S3.Handlers.Build.PushBack(addRequestPayer)
	}
	if s.v2Signer {
		s.setV2Signer(&s.S3.Handlers)
	}
	s.S3.Handlers.Sign.PushBack(addAcceptEncoding)
	s.S3.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "UserAgentHandler",
		Fn:   request.MakeAddToUserAgentHandler("goofys", VersionNumber+"-"+VersionHash),
	})
}

func (s *S3Backend) detectBucketLocationByHEAD() (err error, isAws bool) {
	u := url.URL{
		Scheme: "https",
		Host:   "s3.amazonaws.com",
		Path:   s.bucket,
	}

	if s.awsConfig.Endpoint != nil {
		endpoint, err := url.Parse(*s.awsConfig.Endpoint)
		if err != nil {
			return err, false
		}

		u.Scheme = endpoint.Scheme
		u.Host = endpoint.Host
	}

	var req *http.Request
	var resp *http.Response

	req, err = http.NewRequest("HEAD", u.String(), nil)
	if err != nil {
		return
	}

	allowFails := 3
	for i := 0; i < allowFails; i++ {
		resp, err = http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return
		}
		if resp.StatusCode < 500 {
			break
		} else if resp.StatusCode == 503 && resp.Status == "503 Slow Down" {
			time.Sleep(time.Duration(i+1) * time.Second)
			// allow infinite retries for 503 slow down
			allowFails += 1
		}
	}

	region := resp.Header["X-Amz-Bucket-Region"]
	server := resp.Header["Server"]

	s3Log.Debugf("HEAD %v = %v %v", u.String(), resp.StatusCode, region)
	if region == nil {
		for k, v := range resp.Header {
			s3Log.Debugf("%v = %v", k, v)
		}
	}
	if server != nil && server[0] == "AmazonS3" {
		isAws = true
	}

	switch resp.StatusCode {
	case 200:
		// note that this only happen if the bucket is in us-east-1
		if len(s.config.Profile) == 0 {
			s.awsConfig.Credentials = credentials.AnonymousCredentials
			s3Log.Infof("anonymous bucket detected")
		}
	case 400:
		err = fuse.EINVAL
	case 403:
		err = syscall.EACCES
	case 404:
		err = syscall.ENXIO
	case 405:
		err = syscall.ENOTSUP
	default:
		err = awserr.New(strconv.Itoa(resp.StatusCode), resp.Status, nil)
	}

	if len(region) != 0 {
		if region[0] != *s.awsConfig.Region {
			s3Log.Infof("Switching from region '%v' to '%v'",
				*s.awsConfig.Region, region[0])
			s.awsConfig.Region = &region[0]
		}

		// we detected a region, this is aws, the error is irrelevant
		err = nil
	}

	return
}

func (s *S3Backend) testBucket(key string) (err error) {
	_, err = s.HeadBlob(&HeadBlobInput{Key: key})
	if err != nil {
		if err == fuse.ENOENT {
			err = nil
		}
	}

	return
}

func (s *S3Backend) fallbackV2Signer() (err error) {
	if s.v2Signer {
		return fuse.EINVAL
	}

	s3Log.Infoln("Falling back to v2 signer")
	s.v2Signer = true
	s.newS3()
	return
}

func (s *S3Backend) Init(key string) error {
	var isAws bool
	var err error

	if !s.config.RegionSet {
		err, isAws = s.detectBucketLocationByHEAD()
		if err == nil {
			// we detected a region header, this is probably AWS S3,
			// or we can use anonymous access, or both
			s.newS3()
			s.aws = isAws
		} else if err == syscall.ENXIO {
			return fmt.Errorf("bucket %v does not exist", s.bucket)
		} else {
			// this is NOT AWS, we expect the request to fail with 403 if this is not
			// an anonymous bucket
			if err != syscall.EACCES {
				s3Log.Errorf("Unable to access '%v': %v", s.bucket, err)
			}
		}
	}

	// try again with the credential to make sure
	err = s.testBucket(key)
	if err != nil {
		if !isAws {
			// EMC returns 403 because it doesn't support v4 signing
			// swift3, ceph-s3 returns 400
			// Amplidata just gives up and return 500
			if err == syscall.EACCES || err == fuse.EINVAL || err == syscall.EAGAIN {
				err = s.fallbackV2Signer()
				if err != nil {
					return err
				}
				err = s.testBucket(key)
			}
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *S3Backend) ListObjectsV2(params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, string, error) {
	s3Log.Debugf("ListObjectsV2: params %v, backend %v", params, s)
	if s.aws {
		req, resp := s.S3.ListObjectsV2Request(params)
		err := req.Send()
		if err != nil {
			return nil, "", err
		}
		return resp, s.getRequestId(req), nil
	} else {
		v1 := s3.ListObjectsInput{
			Bucket:       params.Bucket,
			Delimiter:    params.Delimiter,
			EncodingType: params.EncodingType,
			MaxKeys:      params.MaxKeys,
			Prefix:       params.Prefix,
			RequestPayer: params.RequestPayer,
		}
		if params.StartAfter != nil {
			v1.Marker = params.StartAfter
		} else {
			v1.Marker = params.ContinuationToken
		}

		objs, err := s.S3.ListObjects(&v1)
		if err != nil {
			return nil, "", err
		}
		s3Log.Debugf("ListObjectsV2: objs %v, err %v", objs, err)
		count := int64(len(objs.Contents))
		v2Objs := s3.ListObjectsV2Output{
			CommonPrefixes:        objs.CommonPrefixes,
			Contents:              objs.Contents,
			ContinuationToken:     objs.Marker,
			Delimiter:             objs.Delimiter,
			EncodingType:          objs.EncodingType,
			IsTruncated:           objs.IsTruncated,
			KeyCount:              &count,
			MaxKeys:               objs.MaxKeys,
			Name:                  objs.Name,
			NextContinuationToken: objs.NextMarker,
			Prefix:                objs.Prefix,
			StartAfter:            objs.Marker,
		}

		return &v2Objs, "", nil
	}
}

func metadataToLower(m map[string]*string) map[string]*string {
	if m != nil {
		var toDelete []string
		for k, v := range m {
			lower := strings.ToLower(k)
			if lower != k {
				m[lower] = v
				toDelete = append(toDelete, k)
			}
		}
		for _, k := range toDelete {
			delete(m, k)
		}
	}
	return m
}

func (s *S3Backend) getRequestId(r *request.Request) string {
	return r.HTTPResponse.Header.Get("x-amz-request-id") + ": " +
		r.HTTPResponse.Header.Get("x-amz-id-2")
}

func (s *S3Backend) HeadBlob(param *HeadBlobInput) (*HeadBlobOutput, error) {
	s3Log.Debugf("Entering HeadBlob")
	cleanedPath := returnURIPath(s.bucket + param.Key)
	request := createRequest(os.Getenv("BUCKET_HOST"), "HEAD", cleanedPath)
	res, e := s.httpClient.Do(request)
	if e != nil {
		fmt.Println(e)

	}
	// Build the information to be sent in the response
	etag := res.Header.Get("ETag")
	lastModified, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", res.Header.Get("Last-Modified"))
	size, _ := strconv.ParseUint(res.Header.Get("ContentLength"), 10, 64)
	storageClass := res.Header.Get("x-amz-storage-class")
	contentType := res.Header.Get("Content-Type")
	amzRequest := res.Header.Get("x-amz-request-id") + ": " + res.Header.Get("x-amz-id-2")
	amzMeta := make(map[string]*string)
	for key, val := range res.Header {
		if strings.HasPrefix("x-amz-meta-", key) {
			for _, value := range val {
				amzMeta[key] = &value
			}
		}
	}

	s3Log.Debugf("Exiting Headblob")
	return &HeadBlobOutput{
		BlobItemOutput: BlobItemOutput{
			Key:          &param.Key,
			ETag:         &etag,
			LastModified: &lastModified,
			Size:         size,
			StorageClass: &storageClass,
		},
		ContentType: &contentType,
		Metadata:    metadataToLower(amzMeta),
		IsDirBlob:   strings.HasSuffix(param.Key, "/"),
		RequestId:   amzRequest,
	}, nil
}

func (s *S3Backend) ListBlobs(param *ListBlobsInput) (*ListBlobsOutput, error) {
	var maxKeys *int64
	s3Log.Debugf("ListBlobs")
	if param.MaxKeys != nil {
		maxKeys = aws.Int64(int64(*param.MaxKeys))
	}

	resp, reqId, err := s.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket:            &s.bucket,
		Prefix:            param.Prefix,
		Delimiter:         param.Delimiter,
		MaxKeys:           maxKeys,
		StartAfter:        param.StartAfter,
		ContinuationToken: param.ContinuationToken,
	})
	s3Log.Debugf("ListBlobs: resp %v, reqid %v, err %v", resp, reqId, err)
	if err != nil {
		return nil, mapAwsError(err)
	}

	prefixes := make([]BlobPrefixOutput, 0)
	items := make([]BlobItemOutput, 0)

	for _, p := range resp.CommonPrefixes {
		prefixes = append(prefixes, BlobPrefixOutput{Prefix: p.Prefix})
	}
	for _, i := range resp.Contents {
		items = append(items, BlobItemOutput{
			Key:          i.Key,
			ETag:         i.ETag,
			LastModified: i.LastModified,
			Size:         uint64(*i.Size),
			StorageClass: i.StorageClass,
		})
	}
	s3Log.Debugf("ListBlobs: prefixes %v, items %v", prefixes, items)
	isTruncatedFlag := false
	if resp.IsTruncated != nil {
		isTruncatedFlag = *resp.IsTruncated
	} else {
		s3Log.Debugf("ListBlobs: nil pointer catch")
	}
	return &ListBlobsOutput{
		Prefixes:              prefixes,
		Items:                 items,
		NextContinuationToken: resp.NextContinuationToken,
		IsTruncated:           isTruncatedFlag,
		RequestId:             reqId,
	}, nil
}

func (s *S3Backend) DeleteBlob(param *DeleteBlobInput) (*DeleteBlobOutput, error) {
	s3Log.Debugf("Entering DeleteBlob")
	cleanedPath := returnURIPath(s.bucket + param.Key)
	request := createRequest(os.Getenv("BUCKET_HOST"), "DELETE", cleanedPath)
	res, e := s.httpClient.Do(request)
	if e != nil {
		s3Log.Debugf(e.Error())
	}
	amzRequest := res.Header.Get("x-amz-request-id") + ": " + res.Header.Get("x-amz-id-2")
	s3Log.Debugf("Exiting DeleteBlob")
	return &DeleteBlobOutput{amzRequest}, nil
}

func (s *S3Backend) DeleteBlobs(param *DeleteBlobsInput) (*DeleteBlobsOutput, error) {
	num_objs := len(param.Items)

	var items s3.Delete
	var objs = make([]*s3.ObjectIdentifier, num_objs)

	for i, _ := range param.Items {
		objs[i] = &s3.ObjectIdentifier{Key: &param.Items[i]}
	}

	// Add list of objects to delete to Delete object
	items.SetObjects(objs)

	req, _ := s.DeleteObjectsRequest(&s3.DeleteObjectsInput{
		Bucket: &s.bucket,
		Delete: &items,
	})
	err := req.Send()
	if err != nil {
		return nil, mapAwsError(err)
	}

	return &DeleteBlobsOutput{s.getRequestId(req)}, nil
}

func (s *S3Backend) RenameBlob(param *RenameBlobInput) (*RenameBlobOutput, error) {
	return nil, syscall.ENOTSUP
}

func (s *S3Backend) mpuCopyPart(from string, to string, mpuId string, bytes string, part int64,
	sem semaphore, srcEtag *string, etag **string, errout *error) {

	defer sem.P(1)

	// XXX use CopySourceIfUnmodifiedSince to ensure that
	// we are copying from the same object
	params := &s3.UploadPartCopyInput{
		Bucket:            &s.bucket,
		Key:               &to,
		CopySource:        aws.String(url.QueryEscape(from)),
		UploadId:          &mpuId,
		CopySourceRange:   &bytes,
		CopySourceIfMatch: srcEtag,
		PartNumber:        &part,
	}
	if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
		params.CopySourceSSECustomerAlgorithm = PString("AES256")
		params.CopySourceSSECustomerKey = &s.config.SseC
		params.CopySourceSSECustomerKeyMD5 = &s.config.SseCDigest
	}

	s3Log.Debug(params)

	resp, err := s.UploadPartCopy(params)
	if err != nil {
		s3Log.Errorf("UploadPartCopy %v = %v", params, err)
		*errout = mapAwsError(err)
		return
	}

	*etag = resp.CopyPartResult.ETag
	return
}

func sizeToParts(size int64) (int, int64) { // this shouldnt matter, since this mpu shouldnt get called.
	const MAX_S3_MPU_SIZE int64 = 5 * 1024 * 1024 * 1024 * 1024
	if size > MAX_S3_MPU_SIZE {
		panic(fmt.Sprintf("object size: %v exceeds maximum S3 MPU size: %v", size, MAX_S3_MPU_SIZE))
	}

	// Use the maximum number of parts to allow the most server-side copy
	// parallelism.
	const MAX_PARTS = 10 * 1000
	const MIN_PART_SIZE = 50 * 1024 * 1024
	partSize := MaxInt64(size/(MAX_PARTS-1), MIN_PART_SIZE)

	nParts := int(size / partSize)
	if size%partSize != 0 {
		nParts++
	}

	return nParts, partSize
}

func (s *S3Backend) mpuCopyParts(size int64, from string, to string, mpuId string,
	srcEtag *string, etags []*string, partSize int64, err *error) {

	rangeFrom := int64(0)
	rangeTo := int64(0)

	MAX_CONCURRENCY := MinInt(100, len(etags))
	sem := make(semaphore, MAX_CONCURRENCY)
	sem.P(MAX_CONCURRENCY)

	for i := int64(1); rangeTo < size; i++ {
		rangeFrom = rangeTo
		rangeTo = i * partSize
		if rangeTo > size {
			rangeTo = size
		}
		bytes := fmt.Sprintf("bytes=%v-%v", rangeFrom, rangeTo-1)

		sem.V(1)
		go s.mpuCopyPart(from, to, mpuId, bytes, i, sem, srcEtag, &etags[i-1], err)
	}

	sem.V(MAX_CONCURRENCY)
}

// This shouldnt get reached, the only reference to `copyObjectMultip` was commented out (other than the test)
// Assuming that this backend_s3.go is the one that is used.
func (s *S3Backend) copyObjectMultipart(size int64, from string, to string, mpuId string,
	srcEtag *string, metadata map[string]*string, storageClass *string) (requestId string, err error) {
	nParts, partSize := sizeToParts(size) // should be unreachable, and partsize i dont need anything to do with
	etags := make([]*string, nParts)

	if mpuId == "" {
		params := &s3.CreateMultipartUploadInput{ // should be unreachable, assuming this is the one that is used
			Bucket:       &s.bucket,
			Key:          &to,
			StorageClass: storageClass,
			ContentType:  s.flags.GetMimeType(to),
			Metadata:     metadataToLower(metadata),
		}

		if s.config.UseSSE {
			params.ServerSideEncryption = &s.sseType
			if s.config.UseKMS && s.config.KMSKeyID != "" {
				params.SSEKMSKeyId = &s.config.KMSKeyID
			}
		} else if s.config.SseC != "" {
			params.SSECustomerAlgorithm = PString("AES256")
			params.SSECustomerKey = &s.config.SseC
			params.SSECustomerKeyMD5 = &s.config.SseCDigest
		}

		if s.config.ACL != "" {
			params.ACL = &s.config.ACL
		}

		resp, err := s.CreateMultipartUpload(params) // should be unreachable, assuming this is the one that is used.
		if err != nil {
			return "", mapAwsError(err)
		}

		mpuId = *resp.UploadId
	}

	s.mpuCopyParts(size, from, to, mpuId, srcEtag, etags, partSize, &err)

	if err != nil {
		return
	} else {
		parts := make([]*s3.CompletedPart, nParts)
		for i := 0; i < nParts; i++ {
			parts[i] = &s3.CompletedPart{
				ETag:       etags[i],
				PartNumber: aws.Int64(int64(i + 1)),
			}
		}

		params := &s3.CompleteMultipartUploadInput{
			Bucket:   &s.bucket,
			Key:      &to,
			UploadId: &mpuId,
			MultipartUpload: &s3.CompletedMultipartUpload{
				Parts: parts,
			},
		}

		s3Log.Debug(params)

		req, _ := s.CompleteMultipartUploadRequest(params)
		err = req.Send()
		if err != nil {
			s3Log.Errorf("Complete MPU %v = %v", params, err)
			err = mapAwsError(err)
		} else {
			requestId = s.getRequestId(req)
		}
	}

	return
}

func (s *S3Backend) CopyBlob(param *CopyBlobInput) (*CopyBlobOutput, error) {
	metadataDirective := s3.MetadataDirectiveCopy
	s3Log.Debugf("Entering CopyBlob")
	if param.Metadata != nil {
		metadataDirective = s3.MetadataDirectiveReplace
	}

	COPY_LIMIT := uint64(5 * 1024 * 1024 * 1024)

	if param.Size == nil || param.ETag == nil || (*param.Size > COPY_LIMIT &&
		(param.Metadata == nil || param.StorageClass == nil)) {

		params := &HeadBlobInput{Key: param.Source}
		resp, err := s.HeadBlob(params)
		if err != nil {
			return nil, err
		}

		param.Size = &resp.Size
		param.ETag = resp.ETag
		if param.Metadata == nil {
			param.Metadata = resp.Metadata
		}
		param.StorageClass = resp.StorageClass
	}

	if param.StorageClass == nil {
		if *param.Size < 128*1024 && s.config.StorageClass == "STANDARD_IA" {
			param.StorageClass = PString("STANDARD")
		} else {
			param.StorageClass = &s.config.StorageClass
		}
	}

	from := s.bucket + "/" + param.Source

	/*
		if !s.gcs && *param.Size > COPY_LIMIT {
			reqId, err := s.copyObjectMultipart(int64(*param.Size), from, param.Destination, "", param.ETag, param.Metadata, param.StorageClass)
			if err != nil {
				return nil, err
			}
			return &CopyBlobOutput{reqId}, nil
		}
	*/

	params := &s3.CopyObjectInput{
		Bucket:            &s.bucket,
		CopySource:        aws.String(url.QueryEscape(from)),
		Key:               &param.Destination,
		StorageClass:      param.StorageClass,
		ContentType:       s.flags.GetMimeType(param.Destination),
		Metadata:          metadataToLower(param.Metadata),
		MetadataDirective: &metadataDirective,
	}

	s3Log.Debug("CopyBlob params")
	s3Log.Debug(params)

	if s.config.UseSSE {
		params.ServerSideEncryption = &s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			params.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
		params.CopySourceSSECustomerAlgorithm = PString("AES256")
		params.CopySourceSSECustomerKey = &s.config.SseC
		params.CopySourceSSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		params.ACL = &s.config.ACL
	}

	req, _ := s.CopyObjectRequest(params)
	// make a shallow copy of the client so we can change the
	// timeout only for this request but still re-use the
	// connection pool
	c := *(req.Config.HTTPClient)
	req.Config.HTTPClient = &c
	req.Config.HTTPClient.Timeout = 15 * time.Minute
	err := req.Send()
	if err != nil {
		s3Log.Errorf("CopyObject %v = %v", params, err)
		return nil, mapAwsError(err)
	}
	s3Log.Debug("Exiting copyblob")
	return &CopyBlobOutput{s.getRequestId(req)}, nil
}

func generateSignature(timeStampISO8601Format string, timestampYMD string, hashedPayload string, host string, filePath string, method string) string {
	s3Log.Debug("Generating Signature")
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	// must create the Canonical Request
	canonicalRequest := method + "\n"   // HTTP Method
	canonicalRequest += filePath + "\n" // canoniocalURI
	canonicalRequest += "\n"            // canonicalQueryString: what comes after the "?" if none then just \n, if for other functions they need more
	// we will edit it then, but for just get it is empty
	canonicalRequest += "host:" + host + "\n" + // Canonical Headers
		"x-amz-content-sha256:" + hashedPayload + "\n" + // this SHA is that of an empty string, at least for GET
		"x-amz-date:" + timeStampISO8601Format + "\n\n"
	// has to be double newline after last header because theres the newline after each header and then one after the group
	canonicalRequest += "host;x-amz-content-sha256;x-amz-date\n" // signed headers, alphabetically sorted
	canonicalRequest += hashedPayload
	// create string to Sign
	stringToSign := "AWS4-HMAC-SHA256" //algorithm
	stringToSign += "\n" + timeStampISO8601Format
	stringToSign += "\n" + timestampYMD + "/us-east-1/s3/aws4_request\n"
	hash256 := sha256.New()
	hash256.Write([]byte(canonicalRequest))
	stringToSign += hex.EncodeToString(hash256.Sum(nil))
	//Create the signing Key
	dateKey := getHMAC([]byte("AWS4"+os.Getenv("AWS_SECRET_ACCESS_KEY")), []byte(timestampYMD))
	dateRegionKey := getHMAC(dateKey, []byte("us-east-1"))
	dateRegionServiceKey := getHMAC(dateRegionKey, []byte("s3"))
	signingKey := getHMAC(dateRegionServiceKey, []byte("aws4_request"))
	// create the signature
	signature := hex.EncodeToString(getHMAC(signingKey, []byte(stringToSign)))
	return signature
}

func getHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// May need to modify once we get to `PUT`
func createRequest(host string, method string, filePath string) *http.Request {
	// Generate values to be re-used, the date, the hashed payload
	timeStampISO8601Format := time.Now().Format("20060102T150405Z")
	timestampYMD := time.Now().Format("20060102")
	//payload := strings.NewReader("<file contents here>") // just keeping as this as generated by
	payload := strings.NewReader("")
	// Generate hash for payload (in our case currently empty)
	hasher := sha256.New()
	hasher.Write([]byte(""))
	hashedPayload := hex.EncodeToString(hasher.Sum(nil)) // should be e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

	// combine host and filepath to get full url string
	req, err := http.NewRequest(method, "https://"+host+filePath, payload)

	if err != nil {
		fmt.Println(err)
	}
	signature := generateSignature(timeStampISO8601Format, timestampYMD, hashedPayload, host, filePath, method)
	req.Header.Add("X-Amz-Content-Sha256", hashedPayload)
	req.Header.Add("X-Amz-Date", timeStampISO8601Format)
	req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential="+os.Getenv("AWS_ACCESS_KEY_ID")+"/"+timestampYMD+
		"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature="+signature)
	// Example of what the request header should look like below
	// AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
	return req
}

// s.bucket and param.Key combine nicely with good slash management. The final path we want looks something like;
// /bucket/path/path2/.../file.txt
// Example -> s.bucket: 1121045215484495542 and param.Key: jose/new,file.txt
func returnURIPath(fullPath string) string {
	pathToClean := strings.Split(fullPath, `/`)
	cleanedPath := ""
	for i := range pathToClean {
		cleanedPath += "/" + url.QueryEscape(pathToClean[i])
	}
	// Must replace any `+`'s to %20 https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	// the QueryEscape encodes the space to +
	cleanedPath = strings.ReplaceAll(cleanedPath, "+", "%20")
	return cleanedPath
}
func (s *S3Backend) GetBlob(param *GetBlobInput) (*GetBlobOutput, error) {
	cleanedPath := returnURIPath(s.bucket + param.Key)
	request := createRequest(os.Getenv("BUCKET_HOST"), "GET", cleanedPath)
	res, e := s.httpClient.Do(request)
	if e != nil {
		s3Log.Debugf(e.Error())
	}
	// Build the information to be sent in the response
	etag := res.Header.Get("ETag")
	lastModified, _ := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", res.Header.Get("Last-Modified"))
	size, _ := strconv.ParseUint(res.Header.Get("ContentLength"), 10, 64)
	storageClass := res.Header.Get("x-amz-storage-class")
	contentType := res.Header.Get("Content-Type")
	amzRequest := res.Header.Get("x-amz-request-id") + ": " + res.Header.Get("x-amz-id-2")
	amzMeta := make(map[string]*string)
	for key, val := range res.Header {
		if strings.HasPrefix("x-amz-meta-", key) {
			for _, value := range val {
				amzMeta[key] = &value
				s3Log.Debug("Key:" + key + "\nValue:" + value)
			}
		}
	}
	s3Log.Debugf("Exiting GetBlob")
	return &GetBlobOutput{
		HeadBlobOutput: HeadBlobOutput{
			BlobItemOutput: BlobItemOutput{
				Key:          &param.Key, // Does not need to be encoded
				ETag:         &etag,
				LastModified: &lastModified,
				Size:         size,
				StorageClass: &storageClass,
			},
			ContentType: &contentType,
			Metadata:    metadataToLower(amzMeta),
		},
		Body:      io.NopCloser(res.Body), // Without the NopCloser the calling function will not be able to use this
		RequestId: amzRequest,
	}, nil
}

func getDate(resp *http.Response) *time.Time {
	date := resp.Header.Get("Date")
	if date != "" {
		t, err := http.ParseTime(date)
		if err == nil {
			return &t
		}
		s3Log.Warnf("invalidate date for %v: %v",
			resp.Request.URL.Path, date)
	}
	return nil
}

func (s *S3Backend) PutBlob(param *PutBlobInput) (*PutBlobOutput, error) {
	storageClass := s.config.StorageClass
	s3Log.Debug("Entering putblob")
	if param.Size != nil && *param.Size < 128*1024 && storageClass == "STANDARD_IA" {
		storageClass = "STANDARD"
	}

	put := &s3.PutObjectInput{
		Bucket:       &s.bucket,
		Key:          &param.Key,
		Metadata:     metadataToLower(param.Metadata),
		Body:         param.Body,
		StorageClass: &storageClass,
		ContentType:  param.ContentType,
	}
	s3Log.Debugf("PutObjectInput: %v", param)

	if s.config.UseSSE {
		s3Log.Debug("Using SSE")
		put.ServerSideEncryption = &s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			s3Log.Debug("UseKMS and KMSID")
			put.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		s3Log.Debug("SSEC != empty, setting cust algo")
		put.SSECustomerAlgorithm = PString("AES256")
		put.SSECustomerKey = &s.config.SseC
		put.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		s3Log.Debug("Put ACL")
		put.ACL = &s.config.ACL
	}

	req, resp := s.PutObjectRequest(put)
	err := req.Send()
	if err != nil {
		return nil, mapAwsError(err)
	}
	s3Log.Debug("Exiting Putblob")
	return &PutBlobOutput{
		ETag:         resp.ETag,
		LastModified: getDate(req.HTTPResponse),
		StorageClass: &storageClass,
		RequestId:    s.getRequestId(req),
	}, nil
}

// reached from file.go
func (s *S3Backend) MultipartBlobBegin(param *MultipartBlobBeginInput) (*MultipartBlobCommitInput, error) {
	// references API then
	mpu := s3.CreateMultipartUploadInput{
		Bucket:       &s.bucket,
		Key:          &param.Key,
		StorageClass: &s.config.StorageClass,
		ContentType:  param.ContentType,
	}

	if s.config.UseSSE {
		mpu.ServerSideEncryption = &s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			mpu.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		mpu.SSECustomerAlgorithm = PString("AES256")
		mpu.SSECustomerKey = &s.config.SseC
		mpu.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		mpu.ACL = &s.config.ACL
	}

	// again reference API
	resp, err := s.CreateMultipartUpload(&mpu)
	if err != nil {
		s3Log.Errorf("CreateMultipartUpload %v = %v", param.Key, err) // this is the err i get?
		return nil, mapAwsError(err)
	}

	return &MultipartBlobCommitInput{
		Key:      &param.Key,
		Metadata: metadataToLower(param.Metadata),
		UploadId: resp.UploadId,
		Parts:    make([]*string, 10000), // at most 10K parts
	}, nil
}

func (s *S3Backend) MultipartBlobAdd(param *MultipartBlobAddInput) (*MultipartBlobAddOutput, error) {
	en := &param.Commit.Parts[param.PartNumber-1]
	atomic.AddUint32(&param.Commit.NumParts, 1)

	params := s3.UploadPartInput{
		Bucket:     &s.bucket,
		Key:        param.Commit.Key,
		PartNumber: aws.Int64(int64(param.PartNumber)),
		UploadId:   param.Commit.UploadId,
		Body:       param.Body,
	}
	if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
	}
	s3Log.Debug(params)

	req, resp := s.UploadPartRequest(&params)
	err := req.Send()
	if err != nil {
		return nil, mapAwsError(err)
	}

	if *en != nil {
		panic(fmt.Sprintf("etags for part %v already set: %v", param.PartNumber, **en))
	}
	*en = resp.ETag

	return &MultipartBlobAddOutput{s.getRequestId(req)}, nil
}

func (s *S3Backend) MultipartBlobCommit(param *MultipartBlobCommitInput) (*MultipartBlobCommitOutput, error) {
	parts := make([]*s3.CompletedPart, param.NumParts)
	for i := uint32(0); i < param.NumParts; i++ {
		parts[i] = &s3.CompletedPart{
			ETag:       param.Parts[i],
			PartNumber: aws.Int64(int64(i + 1)),
		}
	}

	mpu := s3.CompleteMultipartUploadInput{
		Bucket:   &s.bucket,
		Key:      param.Key,
		UploadId: param.UploadId,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	s3Log.Debug(mpu)

	req, resp := s.CompleteMultipartUploadRequest(&mpu)
	err := req.Send()
	if err != nil {
		return nil, mapAwsError(err)
	}

	s3Log.Debug(resp)

	return &MultipartBlobCommitOutput{
		ETag:         resp.ETag,
		LastModified: getDate(req.HTTPResponse),
		RequestId:    s.getRequestId(req),
	}, nil
}

func (s *S3Backend) MultipartBlobAbort(param *MultipartBlobCommitInput) (*MultipartBlobAbortOutput, error) {
	mpu := s3.AbortMultipartUploadInput{
		Bucket:   &s.bucket,
		Key:      param.Key,
		UploadId: param.UploadId,
	}
	req, _ := s.AbortMultipartUploadRequest(&mpu)
	err := req.Send()
	if err != nil {
		return nil, mapAwsError(err)
	}
	return &MultipartBlobAbortOutput{s.getRequestId(req)}, nil
}

func (s *S3Backend) MultipartExpire(param *MultipartExpireInput) (*MultipartExpireOutput, error) {
	mpu, err := s.ListMultipartUploads(&s3.ListMultipartUploadsInput{
		Bucket: &s.bucket,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}
	s3Log.Debug(mpu)

	now := time.Now()
	for _, upload := range mpu.Uploads {
		expireTime := upload.Initiated.Add(48 * time.Hour)

		if !expireTime.After(now) {
			params := &s3.AbortMultipartUploadInput{
				Bucket:   &s.bucket,
				Key:      upload.Key,
				UploadId: upload.UploadId,
			}
			resp, err := s.AbortMultipartUpload(params)
			s3Log.Debug(resp)

			if mapAwsError(err) == syscall.EACCES {
				break
			}
		} else {
			s3Log.Debugf("Keeping MPU Key=%v Id=%v", *upload.Key, *upload.UploadId)
		}
	}

	return &MultipartExpireOutput{}, nil
}

func (s *S3Backend) RemoveBucket(param *RemoveBucketInput) (*RemoveBucketOutput, error) {
	_, err := s.DeleteBucket(&s3.DeleteBucketInput{Bucket: &s.bucket})
	if err != nil {
		return nil, mapAwsError(err)
	}
	return &RemoveBucketOutput{}, nil
}

func (s *S3Backend) MakeBucket(param *MakeBucketInput) (*MakeBucketOutput, error) {
	_, err := s.CreateBucket(&s3.CreateBucketInput{
		Bucket: &s.bucket,
		ACL:    &s.config.ACL,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}

	if s.config.BucketOwner != "" {
		var owner s3.Tag
		owner.SetKey("Owner")
		owner.SetValue(s.config.BucketOwner)

		param := s3.PutBucketTaggingInput{
			Bucket: &s.bucket,
			Tagging: &s3.Tagging{
				TagSet: []*s3.Tag{&owner},
			},
		}

		for i := 0; i < 10; i++ {
			_, err = s.PutBucketTagging(&param)
			err = mapAwsError((err))
			switch err {
			case nil:
				break
			case syscall.ENXIO, syscall.EINTR:
				s3Log.Infof("waiting for bucket")
				time.Sleep((time.Duration(i) + 1) * 2 * time.Second)
			default:
				s3Log.Errorf("Failed to tag bucket %v: %v", s.bucket, err)
				return nil, err
			}
		}
	}

	return &MakeBucketOutput{}, err
}

func (s *S3Backend) Delegate() interface{} {
	return s
}
