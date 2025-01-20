from hashlib import sha256


def hash(str1, str2=None):
    if str2:
        combined = f"{str1}|||{str2}"
    else:
        combined = str1

    hasher = sha256()
    hasher.update(combined.encode("utf-8"))

    return hasher.hexdigest()


def recurse_and_hash(transactions):

    l = len(transactions)

    if l % 2 == 1:
        transactions += [transactions[-1]]
        l = len(transactions)

    if l == 2:
        return hash(transactions[0], transactions[1])

    partition_idx = l // 2

    left_transactions = transactions[0:partition_idx]
    right_transactions = transactions[partition_idx:]

    left_hash = recurse_and_hash(left_transactions)
    right_hash = recurse_and_hash(right_transactions)

    return hash(left_hash, right_hash)


if __name__ == "__main__":
    try:
        test_cases = int(input("T: "))
        if not 1 <= test_cases <= 10:
            raise ValueError("T must be between 1 and 10")

        all_transactions = []

        for t in range(test_cases):
            number_of_transactions = int(input("N: "))
            if not 1 <= number_of_transactions <= 100:
                raise ValueError("N must be between 1 and 100")

            transactions = []
            for n in range(number_of_transactions):
                transaction = input()
                if not 1 <= len(transaction) <= 100:
                    raise ValueError(
                        "Transaction string length must be between 1 and 100"
                    )
                transactions.append(transaction)

            all_transactions.append(transactions)

        for tr in all_transactions:
            if len(tr) == 1:
                print(hash(tr[0]))
            else:
                print(recurse_and_hash(tr))

    except ValueError as e:
        print(f"Error: {e}")
