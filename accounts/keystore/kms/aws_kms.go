package kms

import (
	"context"
	b64 "encoding/base64"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/log"
)

const AwsKmsPrefix = "aws:kms:"

func Decrypt(dataEncB64 string) (*[]byte, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	client := kms.NewFromConfig(cfg)
	//client := kms.New(kms.Options{}) // use EC2 instance's IAM role

	blob, err := b64.StdEncoding.DecodeString(dataEncB64)
	if err != nil {
		log.Error("error converting string to blob", "err", err.Error())
		return nil, err
	}

	decryptInput := &kms.DecryptInput{
		CiphertextBlob: blob,
	}

	result, err := client.Decrypt(context.Background(), decryptInput)
	if err != nil {
		log.Error("Got error decrypting data", "err", err.Error())
		return nil, err
	}

	return &result.Plaintext, nil
}
