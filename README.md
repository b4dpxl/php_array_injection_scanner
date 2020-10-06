Burp scanner which attempts to discover PHP array injection issues. For each URL or Body parameter (which isn't already an array), it will submit a single value as an array and compare the responses, and also as an array with a second random value.

For example, for:
- `GET /my_page.php?name=fred`

It will call:
- `GET /my_page.php?name[]=fred`
- `GET /my_page.php?name[]=fred&name[]=<random_string>`

It will ignore parameter which are already arrays, including URL encoded versions (e.g. `name%5b%5d=fred`). 

The order of checking is:

1. Change in status code
2. Presence of "Array to <something> conversion in"
3. Straight difference between the response bodies

When doing a straight response body check, it will check if the modified body is the same as a request without the parameter, to try and remove false positives.
