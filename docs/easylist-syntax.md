# EasyList Syntax Reference

A quick guide to writing and understanding EasyList filter rules.

---

## 1. Comments & Sections

- **Comment line**
  Starts with `!`
  ```text
  ! This line is ignored by the ad-blocker
  ```

- **Section header**
  Enclosed in `[]`
  ```text
  [Ad Servers]
  ```

---

## 2. Basic Filters

| Pattern                | Description                                             |
|------------------------|---------------------------------------------------------|
| `||example.com^`       | Block any resource whose hostname ends in `example.com` |
| `|https://ads.foo/`    | Block URLs starting exactly with this string            |
| `example.com/ads`      | Block URLs containing the substring `example.com/ads`   |
| `/banner\.js$/`        | Block URLs matching this regexp (JS-style)              |
| `*tracking.js`         | Block any URL containing `tracking.js`                  |
| `@@||good.example.com^`| Exception: allow resources from `good.example.com`      |

- `*` matches zero or more characters
- `^` is a separator placeholder (matches `:/?=&` or end-of-URL)
- `|` at the start or end anchors the rule to the beginning or end of the URL

**Note on regex filters**
Always wrap the pattern in `/…/` with no flags. E.g.:
```text
/https?:\/\/ads\.(com|net)\/track\?id=\d+/$script
```

---

## 3. Resource-Type & Option Modifiers

Append after a filter using `$` and comma-separated options:

| Option             | Meaning                                                  |
|--------------------|----------------------------------------------------------|
| `script`           | Block JavaScript files                                   |
| `image`            | Block images                                             |
| `stylesheet`       | Block CSS files                                          |
| `object`           | Block Flash, Java, etc.                                  |
| `xmlhttprequest`   | Block XHR/fetch requests                                 |
| `subdocument`      | Block frames / iframes                                   |
| `third-party`      | Only if the request is third-party                       |
| `first-party`      | Only if the request is same-origin                       |
| `domain=`          | Apply only on listed domains                             |
| `genericblock`     | Force generic blocking (ignore site-specific heuristics) |
| `redirect=`        | Redirect matched requests to the given URL               |
| `collapse`         | Hide element and remove its space (cosmetic)             |
| `doc`, `elemhide`  | Force element-hiding mode                                |
| `badfilter`        | Disable a filter (for debugging)                         |
| `removeparam=`     | Strip parameter from matched URLs                        |

**Example**
```text
||adserver.example.com^$script,image,third-party
```

---

## 4. Exceptions

- **Basic exception**
  Begins with `@@`

  ```text
  @@||example.com^$script
  ```

- **Domain-restricted exception**

  ```text
  @@|https://sub.example.com/ads^$image,domain=example.com|~sub.example.com
  ```

- **Negating options**
  Prefix any option with `~` to invert it:

  ```text
  ||ad.example.com^$script,~third-party
  ```

  (Blocks scripts only on first-party pages.)

---

## 5. Element (Cosmetic) Filters

### 5.1 Simple Selectors

- **Page-level**
  ```text
  example.com##.ad-banner
  ```
- **Domain-specific**
  ```text
  ##.global-popup
  ```
- **Exception**
  ```text
  example.com#@#.ad-banner
  ```

### 5.2 Selector Options

| Option          | Meaning                                                     |
|-----------------|-------------------------------------------------------------|
| `#@#`           | Exception to an element-hiding rule                         |
| `:style()`      | Inject custom CSS (e.g. `:style(display:block!important;)`) |
| `:has()`        | Match elements containing a sub-selector                    |
| `:matches-css()`| Match elements by computed CSS property/value               |
| `:xpath()`      | Advanced matching via XPath                                 |

**Example**
```text
example.com##div.ad-frame:style(display:block!important;)
```

---

## 6. Regular-Expression Filters

- **Basic**
  ```text
  /banner-\d+\.js$/$third-party,object
  ```
- **With redirect**
  ```text
  /(ads?|track)\.example\.com\/.*$/$redirect=https://example.com/empty.js
  ```

---

## 7. Redirects

- Redirect matching requests to another URL or data:
  ```text
  ||ads.example.com/banner.js^$redirect=https://example.com/empty.js
  ```

---

## 8. Domain Matching Rules

| Syntax              | Behavior                                       |
|---------------------|------------------------------------------------|
| `||`                | Start of hostname (e.g. `||foo.com^`)          |
| `|http://`          | Start of URL                                   |
| `^`                 | Separator placeholder                          |
| `~` before domain   | Negate domain (not that domain)                |
| Multiple domains    | `domain=example.com|test.com|~ads.example.com` |
