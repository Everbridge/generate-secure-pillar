package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGenerateSecurePillar(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GenerateSecurePillar Suite")
}
