def fibonacci(n):
    if n <= 1:
        return n
    else:
        result = fibonacci(n - 1) + fibonacci(n - 2)
        return result

def main():
    for i in range(10):
        value = fibonacci(i)
        print(f"fibonacci({i}) = {value}")

if __name__ == "__main__":
    main()