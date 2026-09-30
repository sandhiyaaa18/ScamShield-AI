from sms.vectorizer import fit_vectorizers

texts = [

    "verify your account",

    "hello how are you",

    "click here to claim prize"

]

word, char = fit_vectorizers(texts)

print()

print("Word Shape :", word.shape)

print("Character Shape :", char.shape)