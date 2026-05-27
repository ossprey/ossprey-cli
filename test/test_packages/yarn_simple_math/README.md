# Simple Math Project

This project implements basic mathematical operations including addition, subtraction, multiplication, and division. It also includes unit tests to verify the correctness of these operations.

## Project Structure

```
javascript_simple_math
├── src
│   └── index.js          # Implementation of simple math functions
├── test
│   └── simpleMath.test.js # Unit tests for the math functions
├── package.json          # Project metadata and dependencies
└── README.md             # Project documentation
```

## Installation

To get started, clone the repository and navigate to the project directory:

```bash
git clone <repository-url>
cd javascript_simple_math
```

Then, install the necessary dependencies:

```bash
npm install
```

## Running Tests

To run the unit tests, use the following command:

```bash
npm test
```

This will execute the tests defined in `test/simpleMath.test.js` and display the results in the console.

## Usage

You can import the math functions from `src/index.js` in your JavaScript files as follows:

```javascript
const { add, subtract, multiply, divide } = require('./src/index');
```

Then, you can use these functions to perform simple math operations.