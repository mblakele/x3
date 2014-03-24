xquery version "1.0-ml";
(:
 : Bits and pieces of S3 functionality.
 :)
module namespace m="http://blakeley.com/github/x3" ;

declare default function namespace "http://www.w3.org/2005/xpath-functions";

declare namespace http="xdmp:http" ;

declare variable $NL := "&#xA;" ;

declare function m:error(
  $code as xs:string,
  $items as item()*)
as empty-sequence()
{
  error((), 'INGEST-'||$code, $items)
};

declare function m:rfc2616-dateTime(
  $dateTime as xs:dateTime)
as xs:string
{
  format-dateTime(
    adjust-dateTime-to-timezone(
      current-dateTime(),
      timezone-from-date(xs:date("1999-12-31-00:00"))),
    '[FNn,*-3], [D01] [MNn,*-3] [Y0001] [H01]:[m01]:[s01] GMT')
};

declare function m:s3-string-to-sign(
  $method as xs:string,
  $content-md5 as xs:string?,
  $content-type as xs:string?,
  $date as xs:string,
  $headers as xs:string?,
  $bucket as xs:string,
  $path as xs:string,
  $subresource as xs:string?)
as xs:string
{
  $method||$NL
  ||$content-md5||$NL
  ||$content-type||$NL
  ||$date||$NL
  ||$headers ! (.||$NL)
  ||'/'||$bucket||$path
  ||$subresource[.] ! ('?'||.)
};

(: Sign a URL, allowing access for a period of time. :)
declare function m:s3-url-sign(
  $access-key as xs:string,
  $secret-key as xs:string,
  $url as xs:string,
  $expires as xs:dateTime)
as xs:string {
  let $epoch := string(
    xs:unsignedLong(
      ($expires - xs:dateTime('1970-01-01T00:00:00Z'))
      div xs:dayTimeDuration('PT1S')))
  let $host := substring-before(substring-after($url, '://'), '/')
  let $path := substring-after($url, $host) ! (
    if (not(contains(., '?'))) then . else substring-before(., '?'))
  let $bucket := substring-before(substring-after($path, '/'), '/')
  let $path := substring-after($path, $bucket)
  let $subresource := substring-after($path, '?')
  let $signature := m:s3-string-to-sign(
    'GET', (), (), $epoch, (), $bucket, $path, $subresource)
  let $signature := xdmp:hmac-sha1($secret-key, $signature, 'base64')
  return (
    $url
    ||'?AWSAccessKeyId='||$access-key
    ||'&amp;Expires='||$epoch
    ||'&amp;Signature='||xdmp:url-encode($signature))
};

(: Generate an Authorization header value for an S3 GET.
 : http://docs.aws.amazon.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html
 : The $date parameter must conform to RFC2616.
 : Sun, 06 Nov 1994 08:49:37 GMT
 :)
declare function m:s3-auth-headers(
  $access-key as xs:string,
  $secret-key as xs:string,
  $method as xs:string,
  $content-md5 as xs:string?,
  $content-type as xs:string?,
  $date as xs:string,
  $headers as xs:string?,
  $bucket as xs:string,
  $path as xs:string,
  $subresource as xs:string?)
as element()+
{
  element http:Date { $date },
  element http:Authorization {
    'AWS '
    ||$access-key||':'
    ||xdmp:hmac-sha1(
      $secret-key,
      m:s3-string-to-sign(
        $method, $content-md5, $content-type,
        $date, $headers,
        $bucket, $path, $subresource),
      "base64") }
};

declare function m:s3-auth-headers(
  $access-key as xs:string,
  $secret-key as xs:string,
  $method as xs:string,
  $headers as xs:string?,
  $bucket as xs:string,
  $path as xs:string,
  $subresource as xs:string?)
as element()+
{
  m:s3-auth-headers(
    $access-key, $secret-key, $method,
    (), (), m:rfc2616-dateTime(current-dateTime()),
    $headers, $bucket, $path, $subresource)
};

declare function m:s3-auth-headers(
  $access-key as xs:string,
  $secret-key as xs:string,
  $method as xs:string,
  $headers as xs:string?,
  $url as xs:string)
as element()+
{
  let $host := substring-before(substring-after($url, '://'), '/')
  let $path := substring-after($url, $host) ! (
    if (not(contains(., '?'))) then . else substring-before(., '?'))
  let $bucket := substring-before(substring-after($path, '/'), '/')
  let $path := substring-after($path, $bucket)
  let $subresource := substring-after($path, '?')
  return m:s3-auth-headers(
    $access-key, $secret-key,
    'GET', $headers,
    $bucket, $path, $subresource)
};

declare function m:http-handle-response(
  $url as xs:string,
  $response as element(http:response),
  $body as document-node()?,
  $expect as xs:integer+)
as node()*
{
  if ($response/http:code = $expect) then $body/node()
  else m:error(
    'HTTP-'||$response/http:code,
    ($url,
      $response/http:code/string(.),
      xdmp:quote($response),
      xdmp:quote($body)))
};

declare function m:http-handle-response(
  $url as xs:string,
  $response as node()+,
  $expect as xs:integer+)
as item()?
{
  m:http-handle-response(
    $url, head($response), tail($response), $expect)
};

declare function m:http-handle-response(
  $url as xs:string,
  $response as node()+)
as item()?
{
  m:http-handle-response(
    $url, head($response), tail($response), 200)
};

(: As of ML7 the built-in xdmp:document-get etc. functions
 : all take s3://bucket/prefix URLs.
 : But this is how you might do it.
 :)
declare function m:s3-get(
  $access-key as xs:string,
  $secret-key as xs:string,
  $url as xs:string,
  $format as xs:string?)
as item()?
{
  m:http-handle-response(
    $url,
    xdmp:http-get(
      $url,
      <options xmlns="xdmp:http-get">
      {
        $format ! <format xmlns="xdmp:document-get">{ $format }</format>,
        <headers xmlns="xdmp:http">
        {
          m:s3-auth-headers(
            $access-key, $secret-key, 'GET', (), $url)
        }
        </headers>
      }
      </options>))
};
