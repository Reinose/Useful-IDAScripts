# Patch PLT for Intel CET enabled binary

## Authors

[@Reinose](https://github.com/Reinose)

## Description

ELF64 binaries Intel CET enabled disturb IDA Pro < 7.5 with the following error message.
(It is resolved in IDA Pro >= 7.5; [link](https://www.hex-rays.com/products/ida/news/7_5/))

```
Unexpected entries in the PLT stub.
The file might have been modified after linking.
```

This script helps IDA Pro < 7.5 to handle this problem.

## Instructions

1. Load an input binary on IDA Pro
2. Wait until auto-analysis finishes.
3. Exectue the script (`File → Script File...`)

## Notes

* It works when the input binary is well structured.
* Some bugs or imprecise results can exist
* It should be executed **after** the auto-analysis finished.
