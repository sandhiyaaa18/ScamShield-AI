"""
====================================================
ScamShield AI
SMS Vectorizer
====================================================
"""

from scipy.sparse import hstack
from sms.config import *

from sklearn.feature_extraction.text import TfidfVectorizer


# ==========================================
# Word Vectorizer
# ==========================================

word_vectorizer = TfidfVectorizer(

    lowercase=True,

    stop_words=None,

    ngram_range=(1,2),

    min_df=2,

    max_df=0.95,

    sublinear_tf=True

)


# ==========================================
# Character Vectorizer
# ==========================================

char_vectorizer = TfidfVectorizer(

    analyzer="char_wb",

    ngram_range=(3,6),

    min_df=2,

    sublinear_tf=True

)

# ==========================================
# Fit
# ==========================================

def fit_vectorizers(texts):

    word_matrix = word_vectorizer.fit_transform(texts)

    char_matrix = char_vectorizer.fit_transform(texts)

    return word_matrix, char_matrix


# ==========================================
# Transform
# ==========================================

def transform(texts):

    word_matrix = word_vectorizer.transform(texts)

    char_matrix = char_vectorizer.transform(texts)

    return hstack([

        word_matrix,

        char_matrix

    ])