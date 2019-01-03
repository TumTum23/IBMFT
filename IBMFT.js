const crypto = require('crypto');

///// constants taken from IETF draft-cavage-http-signatures-09 /////

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`;

const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`;

const ALGORITHM = 'rsa-sha256';

const METHOD = 'POST';
const PATH = '/foo?param=value&pet=dog';
const HEADERS = {
  Host: 'example.com',
  Date: 'Sun, 05 Jan 2014 21:31:40 GMT',
  'Content-Type': 'application/json',
  Digest: 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
  'Content-Length': 18,
};
const PAYLOAD = '{"hello": "world"}';

const KEY_ID = 'Test';

const EXPECTED_BASIC_TEST_SIGNATURE       = 'qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0='
const EXPECTED_ALL_HEADERS_TEST_SIGNATURE = 'vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE='

///// signature methods /////

function get_signing_string(method: string, path: string, headers: string[]) {
  let signing_string = '(request-target): ' + method.toLowerCase() + ' ' + path;
  for (const key in headers) {
    const value = headers[key];
    signing_string += '\n' + key.toLowerCase() + ': ' + String(value);
  }
  return signing_string;
}

function get_signature(signing_string: string, private_key: string) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signing_string);
  return signer.sign(private_key, 'base64');
}

function get_signature_header_value(key_id: string, algorithm: string, headers: string[], signature: string) {
  let header_names = '(request-target)';
  for (const name in headers) {
    header_names += ' ' + name.toLowerCase();
  }
  let header_value = '';
  header_value += 'keyId="' + key_id + '",';
  header_value += 'algorithm="' + algorithm + '",';
  header_value += 'headers="' + header_names + '",';
  header_value += 'signature="' + signature + '"';
  return header_value;
}

///// test methods /////

// uses the (request-target), host, and date headers
function basic_test() {
  const headers = {};
  headers['Host'] = HEADERS['Host'];
  headers['Date'] = HEADERS['Date'];
  run_test('BASIC TEST', headers, EXPECTED_BASIC_TEST_SIGNATURE);
}

// uses all headers
function all_headers_test() {
  const headers = HEADERS;
  run_test('ALL HEADERS TEST', headers, EXPECTED_ALL_HEADERS_TEST_SIGNATURE);
}

function run_test(name, headers, expected_signature) {
  const signing_string = get_signing_string(METHOD, PATH, headers);
  const signature_base64 = get_signature(signing_string, PRIVATE_KEY);
  const signature_header_value = get_signature_header_value(KEY_ID, ALGORITHM, headers, signature_base64);
  console.log();
  console.log('===================================================');
  console.log(name);
  console.log();
  console.log('signing string:\n' + signing_string);
  console.log();
  console.log('signature_base64:\n' + signature_base64);
  console.log();
  console.log('signature_header_value:\n' + signature_header_value);
  console.log();
  if (signature_base64 === expected_signature) {
    console.log('SUCESS: signature is the same as expected');
  } else {
    console.log('ERROR: signature is different than expected');
  }
}

///// run tests /////

basic_test();
all_headers_test();
