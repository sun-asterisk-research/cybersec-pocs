# CVE-2019-18211 C1 CMS
An issue was discovered in Orckestra C1 CMS through 6.6. The EntityTokenSerializer class in Composite.dll is prone to unvalidated deserialization of wrapped BinaryFormatter payloads, leading to arbitrary remote code execution for any low-privilege user.
# Using
> Only run in Windows

RCE with low-privilege user
```
python .\check.py -u http://localhost:36859 --cookies <cookie> --cmd <cmd>
```
# Ref
https://viblo.asia/p/think-out-of-the-box-trong-viec-tim-kiem-lo-hong-net-deserialization-djeZ1zw8lWz