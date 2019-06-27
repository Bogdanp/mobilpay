#lang racket/base

(require crypto
         gregor
         net/base64
         racket/contract
         racket/format
         racket/function
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
 data->order

 make-customer
 customer?)

(define order? xexpr?)
(define customer? xexpr?)

(struct mobilpay
  (signature pubk privk)
  #:transparent)

(define/contract (make-customer #:business? [business? #f]
                                #:email email
                                #:phone phone
                                #:first-name first-name
                                #:last-name last-name
                                #:address address)
  (->* (#:email non-empty-string?
        #:phone non-empty-string?
        #:first-name non-empty-string?
        #:last-name non-empty-string?
        #:address non-empty-string?)
       (#:business? boolean?)
       xexpr?)
  `(contact_info
    (billing
     ([type ,(if business?
                 "company"
                 "person")])
     (first_name ,first-name)
     (last_name ,last-name)
     (address ,address)
     (email ,email)
     (mobile_phone ,phone))))

(define (path->pk path #:fmt [fmt 'SubjectPublicKeyInfo])
  (call-with-input-file path
    (lambda (in)
      (define data
        (base64-decode
         (string->bytes/utf-8
          (string-join (filter (lambda (line)
                                 (not (and (string-prefix? line "-----")
                                           (string-suffix? line "-----"))))
                               (port->lines in))
                       ""))))

      (datum->pk-key data fmt))))

(define/contract (make-mobilpay #:signature signature
                                #:pubk-path pubk-path
                                #:privk-path privk-path)
  (-> #:signature non-empty-string?
      #:pubk-path path-string?
      #:privk-path path-string?
      mobilpay?)
  (mobilpay signature
            (path->pk pubk-path)
            (path->pk privk-path #:fmt 'PrivateKeyInfo)))

(define/contract (mobilpay-endpoint [which 'production])
  (-> (or/c 'production 'sandbox) non-empty-string?)
  (match which
    ['production "https://secure.mobilpay.ro"]
    ['sandbox    "https://sandboxsecure.mobilpay.ro"]))

(define/contract (make-order mobilpay
                             #:order-id order-id
                             #:currency [currency 'RON]
                             #:amount amount
                             #:description description
                             #:customer [customer #f]
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
        #:customer (or/c false/c customer?)
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
     (details ,description)
     ,@(if customer (list customer) null))
    (params
     ,@(map (lambda (pair)
              `(param (name ,(car pair))
                      (value ,(cdr pair)))) params))
    (url
     (confirm ,confirmation-url)
     (return ,return-url))))

(define/contract (order->data mobilpay order)
  (-> mobilpay? order? (values bytes? bytes?))

  (define data
    (with-output-to-bytes
      (lambda _
        (displayln "<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        (write-xml/content (xexpr->xml order)))))

  (define cipher (get-cipher (list 'rc4 'stream)))
  (define shared-key (generate-cipher-key cipher))
  (define encrypted-data (encrypt cipher shared-key #f data))
  (define encrypted-shared-key (pk-encrypt (mobilpay-pubk mobilpay) shared-key #:pad 'pkcs1-v1.5))
  (values (base64-encode encrypted-data #"")
          (base64-encode encrypted-shared-key #"")))

(define/contract (data->order mobilpay encrypted-data encrypted-shared-key)
  (-> mobilpay? bytes? bytes? (or/c false/c order?))

  (with-handlers ([exn:fail? (lambda _ #f)])
    (define shared-key
      (pk-decrypt (mobilpay-privk mobilpay)
                  (base64-decode encrypted-shared-key)
                  #:pad 'pkcs1-v1.5))

    (define data
      (decrypt (get-cipher (list 'rc4 'stream)) shared-key #f
               (base64-decode encrypted-data)))

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
    (define pk (generate-private-key 'rsa))
    (define client (mobilpay "example" pk pk))

    (define order
      (parameterize ([current-clock (lambda () 0)]
                     [current-timezone "UTC"])
        (make-order client
                    #:order-id "MAT19123"
                    #:amount 7990
                    #:description "Plata pe matchacha.ro"
                    #:confirmation-url "https://example.com/confirm"
                    #:return-url "https://example.com/return")))

    (define order+address
      (parameterize ([current-clock (lambda () 0)]
                     [current-timezone "UTC"])
        (make-order client
                    #:order-id "MAT19124"
                    #:amount 7990
                    #:description "Plata pe matchacha.ro"
                    #:customer (make-customer #:email "bogdan@defn.io"
                                              #:phone "0755555555"
                                              #:first-name "Bogdan"
                                              #:last-name "Popa"
                                              #:address "Someplace")
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
                          (return "https://example.com/return"))))

         (check-equal? order+address
                       '(order
                         ([type "card"]
                          [id "MAT19124"]
                          [timestamp "19700101000000"])
                         (signature "example")
                         (invoice
                          ([currency "RON"]
                           [amount "79.90"])
                          (details "Plata pe matchacha.ro")
                          (contact_info
                           (billing
                            ([type "person"])
                            (first_name "Bogdan")
                            (last_name "Popa")
                            (address "Someplace")
                            (email "bogdan@defn.io")
                            (mobile_phone "0755555555"))))
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

         (check-false (data->order client encrypted-data #"invalid"))
         (check-false (data->order client #"invalid" encrypted-shared-key))))))))
