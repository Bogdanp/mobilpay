#lang racket/base

(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/define
         openssl/libcrypto
         racket/runtime-path)

(define-runtime-path legacy-so '(so "ossl-modules/legacy"))
(define-ffi-definer define-crypto libcrypto)
(define-crypto OSSL_PROVIDER_load (_fun _pointer _string -> _pointer) #:fail (lambda () void))
(void (OSSL_PROVIDER_load #f (if (absolute-path? legacy-so) legacy-so "legacy")))
(void (OSSL_PROVIDER_load #f "default"))
