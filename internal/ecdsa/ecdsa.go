package ecdsa

import (
	"crypto/elliptic"
	"sync"

	"github.com/danielost/ecpoint-wrappers/pkg/ecwrapper"
)

var once *sync.Once
var ecw *ecwrapper.ECWrapper

func getECWrapper() *ecwrapper.ECWrapper {
	once.Do(func() {
		ecw = ecwrapper.NewECWrapper(elliptic.P256())
	})
	return ecw
}
