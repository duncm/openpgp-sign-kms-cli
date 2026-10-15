# Supplemental dependency notices

These crates omit their repository license file from the crates.io package.
The files here are copied unchanged from these pinned upstream revisions:

- [base64-simd-0.8.0.txt](https://raw.githubusercontent.com/Nugine/simd/d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE)
- [vsimd-0.8.0.txt](https://raw.githubusercontent.com/Nugine/simd/d74c030d9dc4f3cae02146d1f497ff62726ef09a/LICENSE)
- [difflib-0.4.0.txt](https://raw.githubusercontent.com/DimaKudosh/difflib/f035fb8e656f27119e23eca9d5b996df14f3885e/LICENSE)

Review these files when updating the corresponding dependencies. Release packaging
fails if any dependency has neither packaged notices nor a versioned supplement.
