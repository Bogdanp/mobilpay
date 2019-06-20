#lang racket/base

(require crypto
         gregor
         net/base64
         racket/contract
         racket/format
         racket/match
         racket/port
         racket/string
         xml)

(provide
 make-mobilpay
 mobilpay?
 mobilpay-endpoint

 make-order
 order?
 order->data
 data->order)

(define order?
  xexpr?)

(struct mobilpay
  (signature pk)
  #:transparent)

(define/contract (make-mobilpay #:signature signature
                                #:pk-path pk-path)
  (-> #:signature non-empty-string?
      #:pk-path path-string?
      mobilpay?)
  (call-with-input-file pk-path
    (lambda (in)
      (define data (port->bytes in))
      (define pk (datum->pk-key data 'RSAPrivateKey))
      (mobilpay signature pk))))

(define/contract (mobilpay-endpoint [which 'production])
  (-> (or/c 'production 'sandbox) non-empty-string?)
  (match which
    ['production "https://secure.mobilpay.ro"]
    ['sandbox    "http://sandboxsecure.mobilpay.ro"]))

(define/contract (make-order mobilpay
                             #:order-id order-id
                             #:currency [currency 'RON]
                             #:amount amount
                             #:description description
                             #:params [params null]
                             #:confirmation-url confirmation-url
                             #:return-url return-url)
  (->* (mobilpay?
        #:order-id non-empty-string?
        #:amount (and/c exact-integer? (integer-in 0 9999900))
        #:description non-empty-string?
        #:confirmation-url non-empty-string?
        #:return-url non-empty-string?)
       (#:currency (or/c 'EUR 'USD 'RON)
        #:params (listof (cons/c non-empty-string? string?)))
       order?)

  `(order
    ([type "card"]
     [id ,order-id]
     [timestamp ,(~t (now) "YYYYMMddHHmmss")])
    (signature ,(mobilpay-signature mobilpay))
    (invoice
     ([currency ,(symbol->string currency)]
      [amount ,(cents->string amount)])
     (details ,description))
    (params
     ,@(map (lambda (pair)
              `(param (name ,(car pair))
                      (value ,(cdr pair)))) params))
    (url
     (confirm ,confirmation-url)
     (return ,return-url))))

(define/contract (order->data mobilpay order)
  (-> mobilpay? order? (values string? string?))

  (define data
    (with-output-to-bytes
      (lambda _
        (displayln "<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        (write-xml/content (xexpr->xml order)))))

  (define cipher (get-cipher (list 'rc4 'stream)))
  (define shared-key (generate-cipher-key cipher))
  (define encrypted-data (encrypt cipher shared-key #"" data))
  (define encrypted-shared-key (pk-encrypt (mobilpay-pk mobilpay) shared-key))
  (values (bytes->string/utf-8 (base64-encode encrypted-data #""))
          (bytes->string/utf-8 (base64-encode encrypted-shared-key #""))))

(define/contract (data->order mobilpay encrypted-data encrypted-shared-key)
  (-> mobilpay? string? string? (or/c false/c order?))

  (with-handlers ([exn:fail? (lambda _ #f)])
    (define shared-key
      (pk-decrypt (mobilpay-pk mobilpay)
                  (base64-decode (string->bytes/utf-8 encrypted-shared-key))))

    (define data
      (decrypt (get-cipher (list 'rc4 'stream)) shared-key #""
               (base64-decode (string->bytes/utf-8 encrypted-data))))

    (string->xexpr (bytes->string/utf-8 data))))

(define (cents->string c)
  (~a (floor (/ c 100)) "." (~a (modulo c 100)
                                #:align 'right
                                #:min-width 2
                                #:pad-string "0")))

(module+ test
  (require crypto/libcrypto
           rackunit
           rackunit/text-ui
           xml/path)

  (parameterize ([crypto-factories (list libcrypto-factory)])
    (define client
      (mobilpay "example" (generate-private-key 'rsa)))

    (define order
      (parameterize ([current-clock (lambda () 0)]
                     [current-timezone "UTC"])
        (make-order client
                    #:order-id "MAT19123"
                    #:amount 7990
                    #:description "Plata pe matchacha.ro"
                    #:confirmation-url "https://example.com/confirm"
                    #:return-url "https://example.com/return")))

    (run-tests
     (test-suite
      "mobilpay"

      (test-suite
       "cents->string"

       (for ([value    '(0      10     130    2595    7990)]
             [expected '("0.00" "0.10" "1.30" "25.95" "79.90")])
         (check-equal? (cents->string value) expected)))

      (test-suite
       "make-order"

       (test-case "generates valid orders"
         (check-equal? order
                       '(order
                         ([type "card"]
                          [id "MAT19123"]
                          [timestamp "19700101000000"])
                         (signature "example")
                         (invoice
                          ([currency "RON"]
                           [amount "79.90"])
                          (details "Plata pe matchacha.ro"))
                         (params)
                         (url
                          (confirm "https://example.com/confirm")
                          (return "https://example.com/return"))))))

      (test-suite
       "order->data"

       (test-case "signs orders cryptographically"
         (define-values (encrypted-data encrypted-shared-key)
           (order->data client order))

         (check-equal? (se-path* '(details) (data->order client encrypted-data encrypted-shared-key))
                       (se-path* '(details) order))))

      (test-suite
       "data->order"

       (test-case "returns #f when an order cannot be decrypted"
         (define-values (encrypted-data encrypted-shared-key)
           (order->data client order))

         (check-false (data->order client encrypted-data "invalid"))
         (check-false (data->order client "invalid" encrypted-shared-key))))))))
