# MaxMind test databases

`GeoIP2-Country-Test.mmdb` and `GeoLite2-ASN-Test.mmdb` are official MaxMind
test fixtures, copied verbatim from
<https://github.com/maxmind/MaxMind-DB/tree/main/test-data>
(Apache-2.0 / MIT dual-licensed by MaxMind, Inc.). They contain a handful of
synthetic networks (81.2.69.0/24 is GB, 1.128.0.0/11 is AS1221 Telstra, ...)
and exist only so the GeoIP reader is exercised against databases MaxMind
actually ships, alongside the fixtures tests generate with mmdbwriter.
