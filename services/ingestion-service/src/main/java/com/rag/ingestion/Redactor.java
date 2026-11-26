package com.rag.ingestion;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Masks secrets and personal data BEFORE indexing: what is not indexed can never be returned or sent out. */
final class Redactor {
    record Rule(Pattern pattern, String replacement) {}

    record Result(String text, int count) {}

    static final List<Rule> RULES = List.of(
        new Rule(Pattern.compile("AKIA[0-9A-Z]{16}"), "[AWS_KEY]"),
        new Rule(Pattern.compile("(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"), "[PRIVATE_KEY]"),
        new Rule(Pattern.compile("\\b[\\w.+-]+@[\\w-]+\\.[\\w.-]+\\b"), "[EMAIL]"),
        new Rule(Pattern.compile("\\b(?:\\d[ -]?){13,16}\\b"), "[CARD]"),
        new Rule(Pattern.compile("(?i)(password|passwd|secret|token|api[_-]?key)\\s*[:=]\\s*\\S+"), "$1=[REDACTED]"));

    private Redactor() {}

    static Result redact(String text) {
        int count = 0;
        for (Rule r : RULES) {
            Matcher m = r.pattern().matcher(text);
            StringBuilder out = new StringBuilder();
            while (m.find()) {
                count++;
                m.appendReplacement(out, r.replacement());
            }
            m.appendTail(out);
            text = out.toString();
        }
        return new Result(text, count);
    }
}
