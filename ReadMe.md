Task: 
* Implement a simple CLI tool that prints lines that contain a match for pattern (like grep but smaller and simpler): 
* Read input lines from stdin. Print matched lines to stdout:
    * ```cat file.txt | minigrep "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"```
* Pattern is a regular expression.
* Use hyperscan_sys (https://docs.rs/hyperscan-sys/latest/hyperscan_sys/) crate for pattern matching.
* Do not forget to add SAFETY: comments and enable clippy lints mentioned in previous slides.
* Please, do not overthink and do not overengineer this task. Implement minimal functionality only.



Tests commands


```
echo user@example.com & echo not-an-email | cargo run -- "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
```

```
type emails.txt | cargo run -- "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
```
```
echo first@example.com second@example.com | cargo run -- "\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"
```

```
echo nothing to see | cargo run -- "foo"
```