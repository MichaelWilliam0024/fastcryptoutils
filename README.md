# FastCryptoUtils

FastCryptoUtils is a Java project designed to provide as many encryption and hashing methods as possible, while also leveraging system resources to accelerate these processes.

## Features

- Multiple encryption and hashing methods.
- Acceleration of cryptographic processes using system resources.
- Improved performance, as demonstrated by the `generateKeyPair` function of the RSA algorithm, which can handle 14 items/minute without acceleration, and 32 items/minute with acceleration.
```sh
$ java -jar test.jar --test-rsa
Testing RSA generateKeyPair function...
Without acceleration: 14 it/m
With acceleration: 32 it/m
```

## Installation

To use FastCryptoUtils in your Maven project, add the following dependency to your `pom.xml` file:

```xml
<dependency>
    <groupId>io.github.MichaelWilliam0024</groupId>
    <artifactId>fastcryptoutils</artifactId>
    <version>LATEST</version>
</dependency>
```

## Usage
After adding the dependency, you can use the FastCryptoUtils library in your Java code.

#### Example
```java
byte[] hash = MD5Algorithm.hash("Hello World!".getBytes());
```
or check our testcase!

## Acceleration Dependencies

FastCryptoUtils leverages acceleration libraries in your local environment to speed up cryptographic processes. Upon startup, the application will connect to our servers to check if the versions of your local acceleration libraries meet the requirements for acceleration. We dynamically adjust the required version numbers based on our ongoing support and testing.

We highly recommend keeping your acceleration libraries updated to the latest version to ensure optimal performance. Don't worry! if your local environment does not support acceleration, FastCryptoUtils will automatically revert to default mode without acceleration.

## Contributing
We welcome contributions from the community. If you would like to contribute to FastCryptoUtils, please fork the repository and submit a pull request with your changes.

## Author
MichaelWilliam0024 - A beginner developer :)

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.