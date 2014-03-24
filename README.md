x3
==

S3 utilities in XQuery for MarkLogic

This includes a function to sign an S3 URL:

    m:s3-url-sign(
      $access-key as xs:string,
      $secret-key as xs:string,
      $url as xs:string,
      $expires as xs:dateTime)
    as xs:string

