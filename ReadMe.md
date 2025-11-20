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