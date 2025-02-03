package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
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
		Resource  interface{} `json:"Resource"` // Changed to interface{} to accommodate array
		Condition struct {
			StringEquals    map[string]string   `json:"StringEquals,omitempty"`
			StringNotEquals map[string][]string `json:"StringNotEquals,omitempty"`
			Null            map[string]string   `json:"Null,omitempty"`
			Bool            map[string]bool     `json:"Bool,omitempty"` // Added Bool for new condition
			ArnLike         map[string][]string `json:"ArnLike,omitempty"`
		} `json:"Condition"`
	} `json:"Statement"`
}

func TestComponent(t *testing.T) {
	awsRegion := "us-east-2"

	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			defer atm.GetAndDestroy("vpc-flow-logs-bucket/basic", "default-test", map[string]interface{}{})
			component := atm.GetAndDeploy("vpc-flow-logs-bucket/basic", "default-test", map[string]interface{}{})
			assert.NotNil(t, component)

			bucketID := atm.Output(component, "vpc_flow_logs_bucket_id")
			assert.NotEmpty(t, bucketID)

			bucketArn := atm.Output(component, "vpc_flow_logs_bucket_arn")
			assert.True(t, strings.HasSuffix(bucketArn, bucketID))

			// Verify that our Bucket has versioning enabled
			actualStatus := aws.GetS3BucketVersioning(t, awsRegion, bucketID)
			expectedStatus := "Suspended"
			assert.Equal(t, expectedStatus, actualStatus)

			policyString := aws.GetS3BucketPolicy(t, awsRegion, bucketID)

			var policy BucketPolicy
			json.Unmarshal([]byte(policyString), &policy)

			statement := policy.Statement[0]

			assert.Equal(t, "ForceSSLOnlyAccess", statement.Sid)
			assert.Equal(t, "s3:*", statement.Action)
			assert.Equal(t, "Deny", statement.Effect)
			assert.ElementsMatch(t, []string{
				fmt.Sprintf("arn:aws:s3:::%s/*", bucketID),
				fmt.Sprintf("arn:aws:s3:::%s", bucketID),
			}, statement.Resource) // Check for multiple resources
			assert.Equal(t, false, statement.Condition.Bool["aws:SecureTransport"]) // Check the Bool condition

			statement = policy.Statement[1]

			assert.Equal(t, "AWSLogDeliveryWrite", statement.Sid)
			assert.Equal(t, "Allow", statement.Effect)
			assert.Equal(t, "delivery.logs.amazonaws.com", statement.Principal.Service)
			assert.Equal(t, "s3:PutObject", statement.Action)
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s/*", bucketID), statement.Resource)
			assert.Equal(t, "bucket-owner-full-control", statement.Condition.StringEquals["s3:x-amz-acl"])

			statement = policy.Statement[2]

			assert.Equal(t, "AWSLogDeliveryAclCheck", statement.Sid)
			assert.Equal(t, "Allow", statement.Effect)
			assert.Equal(t, "delivery.logs.amazonaws.com", statement.Principal.Service)
			assert.Equal(t, "s3:GetBucketAcl", statement.Action)
			assert.Equal(t, fmt.Sprintf("arn:aws:s3:::%s", bucketID), statement.Resource)
		})
	})
}
