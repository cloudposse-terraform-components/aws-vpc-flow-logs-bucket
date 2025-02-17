package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)

type BucketPolicy struct {
	Version   string `json:"Version"`
	Statement []struct {
		Sid       string `json:"Sid,omitempty"`
		Principal struct {
			Service string `json:"Service"`
		} `json:"Principal,omitempty"`
		Effect    string      `json:"Effect"`
		Action    string      `json:"Action"`
		Resource  interface{} `json:"Resource"`
		Condition struct {
			StringEquals    map[string]string   `json:"StringEquals,omitempty"`
			StringNotEquals map[string][]string `json:"StringNotEquals,omitempty"`
			Null            map[string]string   `json:"Null,omitempty"`
			Bool            map[string]bool     `json:"Bool,omitempty"`
			ArnLike         map[string][]string `json:"ArnLike,omitempty"`
		} `json:"Condition"`
	} `json:"Statement"`
}

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "vpc-flow-logs-bucket/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	bucketID := atmos.Output(s.T(), options, "vpc_flow_logs_bucket_id")
	assert.NotEmpty(s.T(), bucketID)

	bucketArn := atmos.Output(s.T(), options, "vpc_flow_logs_bucket_arn")
	assert.True(s.T(), strings.HasSuffix(bucketArn, bucketID))

	actualStatus := aws.GetS3BucketVersioning(s.T(), awsRegion, bucketID)
	expectedStatus := "Suspended"
	assert.Equal(s.T(), expectedStatus, actualStatus)

	policyString := aws.GetS3BucketPolicy(s.T(), awsRegion, bucketID)

	var policy BucketPolicy
	json.Unmarshal([]byte(policyString), &policy)

	statement := policy.Statement[0]
	assert.Equal(s.T(), "ForceSSLOnlyAccess", statement.Sid)
	assert.Equal(s.T(), "s3:*", statement.Action)
	assert.Equal(s.T(), "Deny", statement.Effect)
	assert.ElementsMatch(s.T(), []string{
		fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
		fmt.Sprintf("arn:aws:s3:::%s", bucketID),
	}, statement.Resource)
	assert.Equal(s.T(), false, statement.Condition.Bool["aws:SecureTransport"])

	statement = policy.Statement[1]
	assert.Equal(s.T(), "AWSLogDeliveryWrite", statement.Sid)
	assert.Equal(s.T(), "Allow", statement.Effect)
	assert.Equal(s.T(), "delivery.logs.amazonaws.com", statement.Principal.Service)
	assert.Equal(s.T(), "s3:PutObject", statement.Action)
	assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
	assert.Equal(s.T(), "bucket-owner-full-control", statement.Condition.StringEquals["s3:x-amz-acl"])

	statement = policy.Statement[2]
	assert.Equal(s.T(), "AWSLogDeliveryAclCheck", statement.Sid)
	assert.Equal(s.T(), "Allow", statement.Effect)
	assert.Equal(s.T(), "delivery.logs.amazonaws.com", statement.Principal.Service)
	assert.Equal(s.T(), "s3:GetBucketAcl", statement.Action)
	assert.Equal(s.T(), fmt.Sprintf("arn:aws:s3:::%s", bucketID), statement.Resource)

	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "vpc-flow-logs-bucket/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
