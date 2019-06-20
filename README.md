# mobilpay

A barebones implementation of [mobilpay]'s credit card ordering
interface in Racket.

## Setup

    raco pkg install mobilpay

## Usage

Create a client instance:

```racket
(define mobilpay
  (make-mobilpay #:signature "example"
                 #:pk-path "/path/to/private.key"))
```

*note: the key must be in DER format*

Create an `xexpr?` representing an order:

```racket
(define order
  (make-order mobilpay
              #:order-id "unique-id"
              #:currency 'RON
              #:amount 1090 ;; in cents (i.e. this represents "10.90 RON")
              #:description "Payment for widgets"
              #:confirmation-url "https://example.com/confirmation"
              #:return-url "https://example.com/return"))
```

Encrypt it:

```racket
(define-values (encrypted-order-data encrypted-shared-key)
  (order->data mobilpay order))
```

Send the order to mobilpay:

```html
<form action="(mobilpay-endpoint 'sandbox)" method="POST">
  <input type="hidden" name="data" value="encrypted-data">
  <input type="hidden" name="env_key" value="encrypted-shared-key">
  <button type="submit">Pay now</button>
</form>
```

Mobilpay will send you payment notifications to the
`confirmation-url`.  You can decrypt and turn those into `xexpr?`
values using `data->order`:

```racket
(require xml/se-path)

(define (confirmation-page req)
  (define bindings (request-bindings req))
  (define encrypted-order-data (bytes->string/utf-8 (binding:form-value (bindings-assq #"data" bindings))))
  (define encrypted-shared-key (bytes->string/utf-8 (binding:form-value (bindings-assq #"env_key" bindings))))
  (define order+mobilpay-data
    (data->order mobilpay encrypted-order-data encrypted-shared-key))

  (displayln (se-path* '(mobilpay action) order+mobilpay-data))
  (displayln (se-path* '(mobilpay error) order+mobilpay-data)))

```

You will get multiple payment notifications per payment, each
representing an action that was taken.


[mobilpay]: https://www.mobilpay.ro/public/
