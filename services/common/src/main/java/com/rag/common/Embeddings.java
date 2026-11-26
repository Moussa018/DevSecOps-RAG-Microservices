package com.rag.common;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Text vectorisation by feature hashing: each word (lower case, accents removed) increments one of 384 dimensions,
 * then the vector is normalised (cosine similarity in Qdrant). Computed locally, in pure Java: document content
 * never leaves the cluster to be vectorised. Ingestion and rag must use the same function.
 */
public final class Embeddings {
    public static final int DIM = 384;
    private static final Pattern MARKS = Pattern.compile("\\p{M}+");
    private static final Pattern SPLIT = Pattern.compile("[^\\p{L}\\p{N}]+");

    private Embeddings() {}

    public static float[] embed(String text) {
        float[] v = new float[DIM];
        String plain = MARKS.matcher(Normalizer.normalize(text, Normalizer.Form.NFD)).replaceAll("").toLowerCase(Locale.ROOT);
        for (String word : SPLIT.split(plain)) {
            if (word.length() >= 2) {
                v[Math.floorMod(word.hashCode(), DIM)] += 1f;
            }
        }
        double norm = 0;
        for (float x : v) {
            norm += x * x;
        }
        norm = norm == 0 ? 1 : Math.sqrt(norm);
        for (int i = 0; i < DIM; i++) {
            v[i] = (float) (v[i] / norm);
        }
        return v;
    }
}
