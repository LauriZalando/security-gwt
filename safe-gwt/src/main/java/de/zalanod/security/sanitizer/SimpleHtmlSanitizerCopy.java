/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.zalanod.security.sanitizer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.allen_sauer.gwt.log.client.Log;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import com.google.gwt.regexp.shared.MatchResult;
import com.google.gwt.regexp.shared.RegExp;
import com.google.gwt.safehtml.shared.HtmlSanitizer;
import com.google.gwt.safehtml.shared.SafeHtml;
import com.google.gwt.safehtml.shared.SafeHtmlUtils;

/**
 * A simple and relatively inexpensive HTML sanitizer.
 *
 * <p>This sanitizer accepts the subset of HTML consisting of the following attribute-free tags:
 *
 * <ul>
 *   <li>{@code <b>}, {@code <em>}, {@code <i>}</li>
 *   <li>{@code <h1>}, {@code <h2>}, {@code <h3>}, {@code <h4>}, {@code <h5>}, {@code <h6>}</li>
 *   <li>{@code <ul>}, {@code <ol>}. {@code <li>}</li>
 *   <li>{@code <hr>}</li>
 * </ul>
 *
 * as well as numeric HTML entities and HTML entity references. Any HTML metacharacters that do not appear as part of
 * markup in this subset will be HTML-escaped.
 */
public final class SimpleHtmlSanitizerCopy implements HtmlSanitizer {

    /**
     * A canned policy that allows a number of common formatting elements. (extended with 'em', 'hr')<br/>
     * see https://www.owasp.org/index.php/OWASP_Java_HTML_Sanitizer_Project - HtmlPolicyBuilder
     */
    public static final ImmutableSet<String> ALLOWED_COMMON_INLINE_FORMATTING_ELEMENTS = ImmutableSet.of("center", "b",
            "i", "font", "s", "u", "o", "sup", "sub", "ins", "del", "strong", "strike", "tt", "code", "big", "small",
            "br", "span", "em", "hr");

    /**
     * A canned policy that allows a number of common block elements.<br/>
     * see https://www.owasp.org/index.php/OWASP_Java_HTML_Sanitizer_Project - HtmlPolicyBuilder
     */
    public static final ImmutableSet<String> ALLOWED_COMMON_BLOCK_ELEMENTS = ImmutableSet.of("p", "div", "h1", "h2",
            "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote");

    private static final String STYLE_ATTRIBUTE = "style";

    public static final ImmutableSet<String> GLOBALLY_ALLOWED_ELEMENT_ATTRIBUTES = ImmutableSet.of(STYLE_ATTRIBUTE,
            "id", "class", "title", "lang");

    /**
     * Mapping: element -> allowed attributes
     */
    public static final ImmutableMultimap<String, String> ALLOWED_ELEMENT_ATTRIBUTES;

    static {
        final ImmutableMultimap.Builder<String, String> builder = ImmutableMultimap.builder();
        builder.putAll("p", "align");
        builder.putAll("label", "for");
        builder.putAll("font", "color", "face", "size");
        builder.putAll("img", "src", "name", "alt", "border", "hspace", "vspace", "height", "width", "align");
        builder.putAll("table", "border", "cellpadding", "cellspacing", "bgcolor", "background", "noresize", "align",
            "noresize", "height", "width");
        builder.putAll("td", "background", "bgcolor", "abbr", "axis", "headers", "scope", "nowrap", "height", "width",
            "align", "valign", "charoff", "colspan", "rowspan");
        builder.putAll("th", "background", "bgcolor", "abbr", "axis", "headers", "scope", "nowrap", "height", "width",
            "align", "valign", "charoff", "colspan", "rowspan");
        builder.putAll("tr", "background", "height", "width", "align", "valign", "charoff");
        builder.putAll("thead", "align", "valign", "charoff");
        builder.putAll("tbody", "align", "valign", "charoff");
        builder.putAll("tfood", "align", "valign", "charoff");
        builder.putAll("colgroup", "align", "valign", "charoff", "span", "width");
        builder.putAll("col", "align", "valign", "charoff", "span", "width");

        ALLOWED_ELEMENT_ATTRIBUTES = builder.build();
    }

    /**
     * see https://www.owasp.org/index.php/OWASP_Java_HTML_Sanitizer_Project - org.owasp.html.CssSchema.
     */
    public static final ImmutableSet<String> DEFAULT_CSS_WHITELIST = ImmutableSet.of("-moz-border-radius",
            "-moz-border-radius-bottomleft", "-moz-border-radius-bottomright", "-moz-border-radius-topleft",
            "-moz-border-radius-topright", "-moz-box-shadow", "-moz-outline", "-moz-outline-color",
            "-moz-outline-style", "-moz-outline-width", "-o-text-overflow", "-webkit-border-bottom-left-radius",
            "-webkit-border-bottom-right-radius", "-webkit-border-radius", "-webkit-border-radius-bottom-left",
            "-webkit-border-radius-bottom-right", "-webkit-border-radius-top-left", "-webkit-border-radius-top-right",
            "-webkit-border-top-left-radius", "-webkit-border-top-right-radius", "-webkit-box-shadow", "azimuth",
            "background", "background-attachment", "background-color", "background-position", "background-repeat",
            "border", "border-bottom", "border-bottom-color", "border-bottom-left-radius", "border-bottom-right-radius",
            "border-bottom-style", "border-bottom-width", "border-collapse", "border-color", "border-left",
            "border-left-color", "border-left-style", "border-left-width", "border-radius", "border-right",
            "border-right-color", "border-right-style", "border-right-width", "border-spacing", "border-style",
            "border-top", "border-top-color", "border-top-left-radius", "border-top-right-radius", "border-top-style",
            "border-top-width", "border-width", "box-shadow", "caption-side", "color", "cue", "cue-after", "cue-before",
            "direction", "elevation", "empty-cells", "font", "font-family", "font-size", "font-stretch", "font-style",
            "font-variant", "font-weight", "height", "letter-spacing", "line-height", "list-style",
            "list-style-position", "list-style-type", "margin", "margin-bottom", "margin-left", "margin-right",
            "margin-top", "max-height", "max-width", "min-height", "min-width", "outline", "outline-color",
            "outline-style", "outline-width", "padding", "padding-bottom", "padding-left", "padding-right",
            "padding-top", "pause", "pause-after", "pause-before", "pitch", "pitch-range", "quotes", "richness",
            "speak", "speak-header", "speak-numeral", "speak-punctuation", "speech-rate", "stress", "table-layout",
            "text-align", "text-decoration", "text-indent", "text-overflow", "text-shadow", "text-transform",
            "text-wrap", "unicode-bidi", "vertical-align", "voice-family", "volume", "white-space", "width",
            "word-spacing", "word-wrap", "text-align");

    // From http://issues.apache.org/jira/browse/XALANC-519
    private static final ImmutableSet<String> VALUELESS_ATTRIB_NAMES = ImmutableSet.of("checked", "compact", "declare",
            "defer", "disabled", "ismap", "multiple", "nohref", "noresize", "noshade", "nowrap", "readonly",
            "selected");

    private static final RegExp TAG_PATTERN = RegExp.compile("([a-z][a-zA-Z0-9]*)\\s*(.*)");
    private static final RegExp CSS_PAIR_PATTERN = RegExp.compile("([\\-_a-z][\\-_a-zA-Z0-9]*):(.*)");
    private static char[] EMPTY_IMMUNE_CHAR_ARRAY = new char[0];

    private static final SimpleHtmlSanitizerCopy INSTANCE = new SimpleHtmlSanitizerCopy();

    private final HashSet<String> tagWhiteList;
    private final HashSet<String> cssElementWhiteList;
    private final HashMultimap<String, String> allowedElementAttributes;
    private final HashSet<String> globallyAllowedElementAttributes;
    private final CSSCodec cssCodec;
    private final HTMLEntityCodec htmlEntityCodec;

    // prevent external instantiation
    private SimpleHtmlSanitizerCopy() {
        tagWhiteList = Sets.newHashSet();
        tagWhiteList.addAll(ALLOWED_COMMON_BLOCK_ELEMENTS);
        tagWhiteList.addAll(ALLOWED_COMMON_INLINE_FORMATTING_ELEMENTS);
        tagWhiteList.addAll(ALLOWED_ELEMENT_ATTRIBUTES.keys());

        cssElementWhiteList = Sets.newHashSet();
        cssElementWhiteList.addAll(DEFAULT_CSS_WHITELIST);

        allowedElementAttributes = HashMultimap.create(ALLOWED_ELEMENT_ATTRIBUTES);

        globallyAllowedElementAttributes = Sets.newHashSet(GLOBALLY_ALLOWED_ELEMENT_ATTRIBUTES);
        globallyAllowedElementAttributes.addAll(VALUELESS_ATTRIB_NAMES);

        cssCodec = new CSSCodec();
        htmlEntityCodec = new HTMLEntityCodec();
    }

    /**
     * Return a singleton SimpleHtmlSanitizer instance.
     *
     * @return  the instance
     */
    public static SimpleHtmlSanitizerCopy getInstance() {
        return INSTANCE;
    }

    /**
     * HTML-sanitizes a string.
     *
     * <p>The input string is processed as described above. The result of sanitizing the string is guaranteed to be safe
     * to use (with respect to XSS vulnerabilities) in HTML contexts, and is returned as an instance of the
     * {@link SafeHtml} type.
     *
     * @param   html  the input String
     *
     * @return  a sanitized SafeHtml instance
     */
    public static SafeHtml sanitizeHtml(final String html) {
        Preconditions.checkNotNull(html, "html is null");

        return new SafeHtmlStringCopy(INSTANCE.simpleSanitize(html));
    }

    /*
     * Sanitize a string containing simple HTML markup as defined above. The
     * approach is as follows: We split the string at each occurence of '<'. Each
     * segment thus obtained is inspected to determine if the leading '<' was
     * indeed the start of a whitelisted tag or not. If so, the tag is emitted
     * unescaped, and the remainder of the segment (which cannot contain any
     * additional tags) is emitted in escaped form. Otherwise, the entire segment
     * is emitted in escaped form.
     *
     * In either case, EscapeUtils.htmlEscapeAllowEntities is used to escape,
     * which escapes HTML but does not double escape existing syntactially valid
     * HTML entities.
     */
    private String simpleSanitize(final String text) {
        final StringBuilder sanitized = new StringBuilder(text.length());

        boolean firstSegment = true;
        boolean isValidTag = false;

        final StringBuilder builderForSanitizedAttrSegment = new StringBuilder();

        final ArrayList<String> validTagStack = Lists.newArrayList();

        for (String segment : text.split("<", -1)) {

            if (firstSegment) {

                /*
                 *  the first segment is never part of a valid tag; note that if the
                 *  input string starts with a tag, we will get an empty segment at the
                 *  beginning.
                 */
                firstSegment = false;
                sanitized.append(SafeHtmlUtils.htmlEscapeAllowEntities(segment));
                continue;
            }

            /*
             *  determine if the current segment is the start of an attribute-free tag
             *  or end-tag in our white list
             */
            final String tag = extractTag(segment);
            if (tag != null) {

                if (isEndTag(segment)) {
                    if (!validTagStack.isEmpty()) {
                        isValidTag = validTagStack.get(validTagStack.size() - 1).equals(tag);
                        validTagStack.remove(validTagStack.size() - 1);
                    }

                } else if (!isEndTag(segment) || isValidTag) {
                    isValidTag = isTagDefinedInWhiteList(tag);

                    if (isValidTag) {
                        final String actualTag = extractActualTag(tag);
                        final String attributeSegment = extractAttributeSegment(tag);
                        isValidTag = checkIfAttributesAreInWhiteListAndSanitizeValues(builderForSanitizedAttrSegment,
                                actualTag, attributeSegment);
                    }

                }
            }

            if (isValidTag) {
                final String actualTag = extractActualTag(tag);
                closeValidTag(segment, actualTag, builderForSanitizedAttrSegment, sanitized);
                if (!isEndTag(segment) && hasEndTag(segment)) {
                    validTagStack.add(actualTag);
                }
            } else {
                closeInvalidTag(segment, sanitized);
            }

            builderForSanitizedAttrSegment.setLength(0);
        }

        return sanitized.toString();
    }

    private boolean isTagDefinedInWhiteList(final String tag) {
        final String actualTag = extractActualTag(tag);
        if (Strings.isNullOrEmpty(actualTag)) {
            Log.warn("could not parse tag '" + tag + "' --> assuming tag is not white-listed");
            return false;
        } else {
            return tagWhiteList.contains(actualTag);
        }
    }

    private String extractActualTag(final String tag) {
        final MatchResult tagPatternMatcher = TAG_PATTERN.exec(tag);
        if (tagPatternMatcher == null) {
            return "";
        }

        return Strings.nullToEmpty(tagPatternMatcher.getGroup(1)).trim();
    }

    private String extractAttributeSegment(final String tag) {
        final MatchResult tagPatternMatcher = TAG_PATTERN.exec(tag);
        if (tagPatternMatcher == null) {
            return "";
        }

        return Strings.nullToEmpty(tagPatternMatcher.getGroup(2)).trim();
    }

    private void closeValidTag(final String segment, final String tag,
            final StringBuilder builderForSanitizedAttrSegment, final StringBuilder sanitized) {

        // append the tag, not escaping it
        if (isEndTag(segment)) {

            // we had seen an end-tag
            sanitized.append("</");
        } else {
            sanitized.append('<');
        }

        sanitized.append(tag);
        if (builderForSanitizedAttrSegment.length() > 0) {

            // due to http://code.google.com/p/google-web-toolkit/issues/detail?id=4097 we have to use the .toString()
            // method here. might be fixed for newer gwt versions. causes troubles only in debug mode
            sanitized.append(' ').append(builderForSanitizedAttrSegment.toString());
        }

        if (hasEndTag(segment)) {
            sanitized.append('>');
        } else {
            sanitized.append("/>");
        }

        // append the rest of the segment, escaping it
        sanitized.append(SafeHtmlUtils.htmlEscapeAllowEntities(segment.substring(segment.indexOf('>') + 1)));
    }

    private void closeInvalidTag(final String segment, final StringBuilder sanitized) {

        // just escape the whole segment
        sanitized.append("&lt;").append(SafeHtmlUtils.htmlEscapeAllowEntities(segment));
    }

    private String extractTag(final String segment) {

        final String correctedSegment = cleanSegment(segment);

        int tagStart = 0; // will be 1 if this turns out to be an end tag.
        int tagEnd = correctedSegment.indexOf('>');
        if (tagEnd > 0) {
            if (isEndTag(correctedSegment)) {
                tagStart = 1;
            } else if (correctedSegment.charAt(tagEnd - 1) == '/') {

                // e.g. <br/>
                tagEnd--;
            }

            // NOTE: tag contains elements as well if any
            // everything is normalized to lower case strings in our configuration

            return correctedSegment.substring(tagStart, tagEnd).toLowerCase();
        } else {
            return null;
        }
    }

    private String cleanSegment(final String segment) {
        return segment.replaceAll("/\\s*>", "/>");
    }

    private boolean isEndTag(final String segment) {
        return segment.charAt(0) == '/';
    }

    private boolean hasEndTag(final String segment) {
        final String correctedSegment = cleanSegment(segment);
        final int tagEnd = correctedSegment.indexOf('>');

        return correctedSegment.charAt(tagEnd - 1) != '/';
    }

    private boolean checkIfAttributesAreInWhiteListAndSanitizeValues(final StringBuilder builderForSanitizedAttrSegment,
            final String tag, final String attributeSegment) {

        if (attributeSegment.isEmpty()) {

            // no attributes -> no problem
            return true;
        }

        final String[] attributeSegmentSplit = attributeSegment.split("=\\s*|['\"]\\s+");

        int numberOfValueLessAttributes = 0;
        boolean styleAttributeMode = false;

        for (int i = 0; i < attributeSegmentSplit.length; i++) {
            if (styleAttributeMode || (i + 1 + numberOfValueLessAttributes) % 2 == 0) {

                // attribute value

                final String attributeValue = attributeSegmentSplit[i];

                if (styleAttributeMode) {

                    final StringBuilder sanitizedCssBuilder = new StringBuilder(attributeValue.length());
                    final boolean isCssDefinedInWhiteList = checkIfCssIsDefinedInWhiteListAndSanitize(
                            sanitizedCssBuilder, attributeValue);
                    if (isCssDefinedInWhiteList) {

                        // due to http://code.google.com/p/google-web-toolkit/issues/detail?id=4097 we have to use the
                        // .toString() method here. might be fixed for newer gwt versions. causes troubles only in
                        // debug mode
                        builderForSanitizedAttrSegment.append("='").append(sanitizedCssBuilder.toString()).append('\'');
                    } else {
                        return false;
                    }

                    styleAttributeMode = false;
                } else {
                    final String actualValue = peelOutValueFromQuotationMarks(attributeValue);
                    final String sanitizedAttributeValue = htmlEntityCodec.encode(EMPTY_IMMUNE_CHAR_ARRAY, actualValue);
                    builderForSanitizedAttrSegment.append("='").append(sanitizedAttributeValue).append('\'');
                }

            } else {
                // -- attribute name

                final String attributeName = attributeSegmentSplit[i].toLowerCase();

                if (globallyAllowedElementAttributes.contains(attributeName)) {
                    if (STYLE_ATTRIBUTE.equals(attributeName)) {
                        styleAttributeMode = true;
                    } else if (VALUELESS_ATTRIB_NAMES.contains(attributeName)) {
                        numberOfValueLessAttributes++;
                    }
                } else {
                    final Set<String> allowedAttributes = allowedElementAttributes.get(tag);
                    if (!allowedAttributes.contains(attributeName)) {
                        return false;
                    }
                }

                builderForSanitizedAttrSegment.append(' ').append(attributeName);
            }
        }

        return true;
    }

    private boolean checkIfCssIsDefinedInWhiteListAndSanitize(final StringBuilder builderForSanitizedCss,
            final String styleValueEntry) {

        // style values are always surrounded by " or '
        final String prepared = peelOutValueFromQuotationMarks(styleValueEntry);
        final String[] cssPairs = prepared.split(";");

        for (String cssPair : cssPairs) {

            if (cssPair.trim().isEmpty()) {
                continue;
            }

            final MatchResult cssPairPatternMatcher = CSS_PAIR_PATTERN.exec(cssPair);
            if (cssPairPatternMatcher == null) {
                Log.warn("could not parse CSS entry '" + styleValueEntry
                        + " --> assuming style element is not white-listed");
                return false;
            } else {
                final String cssAttributeName = cssPairPatternMatcher.getGroup(1);
                if (cssElementWhiteList.contains(cssAttributeName)) {

                    final String sanitizedCssValue = cssCodec.encode(EMPTY_IMMUNE_CHAR_ARRAY,
                            cssPairPatternMatcher.getGroup(2).trim());
                    builderForSanitizedCss.append(cssAttributeName).append(':').append(sanitizedCssValue).append("; ");
                } else {
                    return false;
                }
            }
        }

        return true;
    }

    private String peelOutValueFromQuotationMarks(final String value) {

        final String trimmed = Strings.nullToEmpty(value).trim();

        if (trimmed.isEmpty()) {
            return trimmed;
        } else {
            return trimmed.substring(1, trimmed.length() - 1);
        }
    }

    /*
     * Note: We purposely do not provide a method to create a SafeHtml from
     * another (arbitrary) SafeHtml via sanitization, as this would permit the
     * construction of SafeHtml objects that are not stable in the sense that for
     * a {@code SafeHtml s} it may not be true that {@code s.asString()} equals
     * {@code SimpleHtmlSanitizer.sanitizeHtml(s.asString()).asString()}. While
     * this is not currently an issue, it might become one and result in
     * unexpected behavior if this class were to become serializable and enforce
     * its class invariant upon deserialization.
     */

    public SafeHtml sanitize(final String html) {
        return sanitizeHtml(html);
    }

    // ---------------------------------------------------------------
    // Following classes are needed for encoding CSS. They can not placed to their own source files
    // because the hack would not in this case (sources are not visible for hacked modules)
    // ---------------------------------------------------------------

    /**
     * The Codec interface defines a set of methods for encoding and decoding application level encoding schemes, such
     * as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding and
     * canonicalization. The design of these codecs allows for character-by-character decoding, which is necessary to
     * detect double-encoding and the use of multiple encoding schemes, both of which are techniques used by attackers
     * to bypass validation and bury encoded attacks in data.
     *
     * @author  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect
     *          Security</a>
     * @since   June 1, 2007
     */
    private abstract static class Codec {

        /**
         * Initialize an array to mark which characters are to be encoded. Store the hex string for that character to
         * save time later. If the character shouldn't be encoded, then store null.
         */
        private static final String[] hex = new String[256];

        static {
            for (char c = 0; c < 0xFF; c++) {
                if (c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A) {
                    hex[c] = null;
                } else {
                    hex[c] = toHex(c).intern();
                }
            }
        }

        /**
         * Encode a String so that it can be safely used in a specific context.
         *
         * @param   immune
         * @param   input   the String to encode
         *
         * @return  the encoded String
         */
        public String encode(final char[] immune, final String input) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                sb.append(encodeCharacter(immune, c));
            }

            return sb.toString();
        }

        /**
         * Default implementation that should be overridden in specific codecs.
         *
         * @param   immune
         * @param   c       the Character to encode
         *
         * @return  the encoded Character
         */
        public String encodeCharacter(final char[] immune, final Character c) {
            return String.valueOf(c);
        }

        /**
         * Lookup the hex value of any character that is not alphanumeric.
         *
         * @param   c  The character to lookup.
         *
         * @return  , return null if alphanumeric or the character code in hex.
         */
        public static String getHexForNonAlphanumeric(final char c) {
            if (c < 0xFF) {
                return hex[c];
            }

            return toHex(c);
        }

        public static String toOctal(final char c) {
            return Integer.toOctalString(c);
        }

        public static String toHex(final char c) {
            return Integer.toHexString(c);
        }

        /**
         * Utility to search a char[] for a specific char.
         *
         * @param   c
         * @param   array
         *
         * @return
         */
        public static boolean containsCharacter(final char c, final char[] array) {
            for (char ch : array) {
                if (c == ch) {
                    return true;
                }
            }

            return false;
        }

    }

    /**
     * OWASP Enterprise Security API (ESAPI). This file is part of the Open Web Application Security Project (OWASP)
     * Enterprise Security API (ESAPI) project. For details, please see <a href="http://www.owasp.org/index.php/ESAPI">
     * http://www.owasp.org/index.php/ESAPI</a>. Copyright (c) 2007 - The OWASP Foundation The ESAPI is published by
     * OWASP under the BSD license. You should read and accept the LICENSE before you use, modify, and/or redistribute
     * this software.
     *
     * @author   Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
     * @created  2007
     */
    /**
     * Implementation of the Codec interface for backslash encoding used in CSS.
     *
     * @author  Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect
     *          Security</a>
     * @since   June 1, 2007
     */
    private static final class CSSCodec extends Codec {

        /**
         * {@inheritDoc} Returns backslash encoded character.
         *
         * @param  immune
         */
        public String encodeCharacter(final char[] immune, final Character c) {

            // check for immune characters
            if (containsCharacter(c, immune)) {
                return String.valueOf(c);
            }

            // check for alphanumeric characters
            String hex = getHexForNonAlphanumeric(c);
            if (hex == null) {
                return String.valueOf(c);
            }

            // return the hex and end in whitespace to terminate
            return "\\" + hex + " ";
        }

        public String encode(final char[] immune, final String input) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                sb.append(encodeCharacter(immune, c));
            }

            return sb.toString();
        }
    }

    private static final class HTMLEntityCodec extends Codec {
        private static final char REPLACEMENT_CHAR = '\ufffd';
        private static final String REPLACEMENT_HEX = "fffd";
        private static final Map<Character, String> characterToEntityMap = mkCharacterToEntityMap();

        /**
         * {@inheritDoc} Encodes a Character for safe use in an HTML entity field.
         *
         * @param  immune
         */
        public String encodeCharacter(final char[] immune, Character c) {

            // check for immune characters
            if (containsCharacter(c, immune)) {
                return "" + c;
            }

            // check for alphanumeric characters
            String hex = Codec.getHexForNonAlphanumeric(c);
            if (hex == null) {
                return "" + c;
            }

            // check for illegal characters
            if ((c <= 0x1f && c != '\t' && c != '\n' && c != '\r') || (c >= 0x7f && c <= 0x9f)) {
                hex = REPLACEMENT_HEX; // Let's entity encode this instead of returning it
                c = REPLACEMENT_CHAR;
            }

            // check if there's a defined entity
            String entityName = characterToEntityMap.get(c);
            if (entityName != null) {
                return "&" + entityName + ";";
            }

            // return the hex entity as suggested in the spec
            return "&#x" + hex + ";";
        }

        /**
         * Build a unmodifiable Map from entity Character to Name.
         *
         * @return  Unmodifiable map.
         */
        private static synchronized Map<Character, String> mkCharacterToEntityMap() {
            final HashMap<Character, String> map = Maps.newHashMapWithExpectedSize(252);

            map.put((char) 34, "quot");      /* quotation mark */
            map.put((char) 38, "amp");       /* ampersand */
            map.put((char) 60, "lt");        /* less-than sign */
            map.put((char) 62, "gt");        /* greater-than sign */
            map.put((char) 160, "nbsp");     /* no-break space */
            map.put((char) 161, "iexcl");    /* inverted exclamation mark */
            map.put((char) 162, "cent");     /* cent sign */
            map.put((char) 163, "pound");    /* pound sign */
            map.put((char) 164, "curren");   /* currency sign */
            map.put((char) 165, "yen");      /* yen sign */
            map.put((char) 166, "brvbar");   /* broken bar */
            map.put((char) 167, "sect");     /* section sign */
            map.put((char) 168, "uml");      /* diaeresis */
            map.put((char) 169, "copy");     /* copyright sign */
            map.put((char) 170, "ordf");     /* feminine ordinal indicator */
            map.put((char) 171, "laquo");    /* left-pointing double angle quotation mark */
            map.put((char) 172, "not");      /* not sign */
            map.put((char) 173, "shy");      /* soft hyphen */
            map.put((char) 174, "reg");      /* registered sign */
            map.put((char) 175, "macr");     /* macron */
            map.put((char) 176, "deg");      /* degree sign */
            map.put((char) 177, "plusmn");   /* plus-minus sign */
            map.put((char) 178, "sup2");     /* superscript two */
            map.put((char) 179, "sup3");     /* superscript three */
            map.put((char) 180, "acute");    /* acute accent */
            map.put((char) 181, "micro");    /* micro sign */
            map.put((char) 182, "para");     /* pilcrow sign */
            map.put((char) 183, "middot");   /* middle dot */
            map.put((char) 184, "cedil");    /* cedilla */
            map.put((char) 185, "sup1");     /* superscript one */
            map.put((char) 186, "ordm");     /* masculine ordinal indicator */
            map.put((char) 187, "raquo");    /* right-pointing double angle quotation mark */
            map.put((char) 188, "frac14");   /* vulgar fraction one quarter */
            map.put((char) 189, "frac12");   /* vulgar fraction one half */
            map.put((char) 190, "frac34");   /* vulgar fraction three quarters */
            map.put((char) 191, "iquest");   /* inverted question mark */
            map.put((char) 192, "Agrave");   /* Latin capital letter a with grave */
            map.put((char) 193, "Aacute");   /* Latin capital letter a with acute */
            map.put((char) 194, "Acirc");    /* Latin capital letter a with circumflex */
            map.put((char) 195, "Atilde");   /* Latin capital letter a with tilde */
            map.put((char) 196, "Auml");     /* Latin capital letter a with diaeresis */
            map.put((char) 197, "Aring");    /* Latin capital letter a with ring above */
            map.put((char) 198, "AElig");    /* Latin capital letter ae */
            map.put((char) 199, "Ccedil");   /* Latin capital letter c with cedilla */
            map.put((char) 200, "Egrave");   /* Latin capital letter e with grave */
            map.put((char) 201, "Eacute");   /* Latin capital letter e with acute */
            map.put((char) 202, "Ecirc");    /* Latin capital letter e with circumflex */
            map.put((char) 203, "Euml");     /* Latin capital letter e with diaeresis */
            map.put((char) 204, "Igrave");   /* Latin capital letter i with grave */
            map.put((char) 205, "Iacute");   /* Latin capital letter i with acute */
            map.put((char) 206, "Icirc");    /* Latin capital letter i with circumflex */
            map.put((char) 207, "Iuml");     /* Latin capital letter i with diaeresis */
            map.put((char) 208, "ETH");      /* Latin capital letter eth */
            map.put((char) 209, "Ntilde");   /* Latin capital letter n with tilde */
            map.put((char) 210, "Ograve");   /* Latin capital letter o with grave */
            map.put((char) 211, "Oacute");   /* Latin capital letter o with acute */
            map.put((char) 212, "Ocirc");    /* Latin capital letter o with circumflex */
            map.put((char) 213, "Otilde");   /* Latin capital letter o with tilde */
            map.put((char) 214, "Ouml");     /* Latin capital letter o with diaeresis */
            map.put((char) 215, "times");    /* multiplication sign */
            map.put((char) 216, "Oslash");   /* Latin capital letter o with stroke */
            map.put((char) 217, "Ugrave");   /* Latin capital letter u with grave */
            map.put((char) 218, "Uacute");   /* Latin capital letter u with acute */
            map.put((char) 219, "Ucirc");    /* Latin capital letter u with circumflex */
            map.put((char) 220, "Uuml");     /* Latin capital letter u with diaeresis */
            map.put((char) 221, "Yacute");   /* Latin capital letter y with acute */
            map.put((char) 222, "THORN");    /* Latin capital letter thorn */
            map.put((char) 223, "szlig");    /* Latin small letter sharp sXCOMMAX German Eszett */
            map.put((char) 224, "agrave");   /* Latin small letter a with grave */
            map.put((char) 225, "aacute");   /* Latin small letter a with acute */
            map.put((char) 226, "acirc");    /* Latin small letter a with circumflex */
            map.put((char) 227, "atilde");   /* Latin small letter a with tilde */
            map.put((char) 228, "auml");     /* Latin small letter a with diaeresis */
            map.put((char) 229, "aring");    /* Latin small letter a with ring above */
            map.put((char) 230, "aelig");    /* Latin lowercase ligature ae */
            map.put((char) 231, "ccedil");   /* Latin small letter c with cedilla */
            map.put((char) 232, "egrave");   /* Latin small letter e with grave */
            map.put((char) 233, "eacute");   /* Latin small letter e with acute */
            map.put((char) 234, "ecirc");    /* Latin small letter e with circumflex */
            map.put((char) 235, "euml");     /* Latin small letter e with diaeresis */
            map.put((char) 236, "igrave");   /* Latin small letter i with grave */
            map.put((char) 237, "iacute");   /* Latin small letter i with acute */
            map.put((char) 238, "icirc");    /* Latin small letter i with circumflex */
            map.put((char) 239, "iuml");     /* Latin small letter i with diaeresis */
            map.put((char) 240, "eth");      /* Latin small letter eth */
            map.put((char) 241, "ntilde");   /* Latin small letter n with tilde */
            map.put((char) 242, "ograve");   /* Latin small letter o with grave */
            map.put((char) 243, "oacute");   /* Latin small letter o with acute */
            map.put((char) 244, "ocirc");    /* Latin small letter o with circumflex */
            map.put((char) 245, "otilde");   /* Latin small letter o with tilde */
            map.put((char) 246, "ouml");     /* Latin small letter o with diaeresis */
            map.put((char) 247, "divide");   /* division sign */
            map.put((char) 248, "oslash");   /* Latin small letter o with stroke */
            map.put((char) 249, "ugrave");   /* Latin small letter u with grave */
            map.put((char) 250, "uacute");   /* Latin small letter u with acute */
            map.put((char) 251, "ucirc");    /* Latin small letter u with circumflex */
            map.put((char) 252, "uuml");     /* Latin small letter u with diaeresis */
            map.put((char) 253, "yacute");   /* Latin small letter y with acute */
            map.put((char) 254, "thorn");    /* Latin small letter thorn */
            map.put((char) 255, "yuml");     /* Latin small letter y with diaeresis */
            map.put((char) 338, "OElig");    /* Latin capital ligature oe */
            map.put((char) 339, "oelig");    /* Latin small ligature oe */
            map.put((char) 352, "Scaron");   /* Latin capital letter s with caron */
            map.put((char) 353, "scaron");   /* Latin small letter s with caron */
            map.put((char) 376, "Yuml");     /* Latin capital letter y with diaeresis */
            map.put((char) 402, "fnof");     /* Latin small letter f with hook */
            map.put((char) 710, "circ");     /* modifier letter circumflex accent */
            map.put((char) 732, "tilde");    /* small tilde */
            map.put((char) 913, "Alpha");    /* Greek capital letter alpha */
            map.put((char) 914, "Beta");     /* Greek capital letter beta */
            map.put((char) 915, "Gamma");    /* Greek capital letter gamma */
            map.put((char) 916, "Delta");    /* Greek capital letter delta */
            map.put((char) 917, "Epsilon");  /* Greek capital letter epsilon */
            map.put((char) 918, "Zeta");     /* Greek capital letter zeta */
            map.put((char) 919, "Eta");      /* Greek capital letter eta */
            map.put((char) 920, "Theta");    /* Greek capital letter theta */
            map.put((char) 921, "Iota");     /* Greek capital letter iota */
            map.put((char) 922, "Kappa");    /* Greek capital letter kappa */
            map.put((char) 923, "Lambda");   /* Greek capital letter lambda */
            map.put((char) 924, "Mu");       /* Greek capital letter mu */
            map.put((char) 925, "Nu");       /* Greek capital letter nu */
            map.put((char) 926, "Xi");       /* Greek capital letter xi */
            map.put((char) 927, "Omicron");  /* Greek capital letter omicron */
            map.put((char) 928, "Pi");       /* Greek capital letter pi */
            map.put((char) 929, "Rho");      /* Greek capital letter rho */
            map.put((char) 931, "Sigma");    /* Greek capital letter sigma */
            map.put((char) 932, "Tau");      /* Greek capital letter tau */
            map.put((char) 933, "Upsilon");  /* Greek capital letter upsilon */
            map.put((char) 934, "Phi");      /* Greek capital letter phi */
            map.put((char) 935, "Chi");      /* Greek capital letter chi */
            map.put((char) 936, "Psi");      /* Greek capital letter psi */
            map.put((char) 937, "Omega");    /* Greek capital letter omega */
            map.put((char) 945, "alpha");    /* Greek small letter alpha */
            map.put((char) 946, "beta");     /* Greek small letter beta */
            map.put((char) 947, "gamma");    /* Greek small letter gamma */
            map.put((char) 948, "delta");    /* Greek small letter delta */
            map.put((char) 949, "epsilon");  /* Greek small letter epsilon */
            map.put((char) 950, "zeta");     /* Greek small letter zeta */
            map.put((char) 951, "eta");      /* Greek small letter eta */
            map.put((char) 952, "theta");    /* Greek small letter theta */
            map.put((char) 953, "iota");     /* Greek small letter iota */
            map.put((char) 954, "kappa");    /* Greek small letter kappa */
            map.put((char) 955, "lambda");   /* Greek small letter lambda */
            map.put((char) 956, "mu");       /* Greek small letter mu */
            map.put((char) 957, "nu");       /* Greek small letter nu */
            map.put((char) 958, "xi");       /* Greek small letter xi */
            map.put((char) 959, "omicron");  /* Greek small letter omicron */
            map.put((char) 960, "pi");       /* Greek small letter pi */
            map.put((char) 961, "rho");      /* Greek small letter rho */
            map.put((char) 962, "sigmaf");   /* Greek small letter final sigma */
            map.put((char) 963, "sigma");    /* Greek small letter sigma */
            map.put((char) 964, "tau");      /* Greek small letter tau */
            map.put((char) 965, "upsilon");  /* Greek small letter upsilon */
            map.put((char) 966, "phi");      /* Greek small letter phi */
            map.put((char) 967, "chi");      /* Greek small letter chi */
            map.put((char) 968, "psi");      /* Greek small letter psi */
            map.put((char) 969, "omega");    /* Greek small letter omega */
            map.put((char) 977, "thetasym"); /* Greek theta symbol */
            map.put((char) 978, "upsih");    /* Greek upsilon with hook symbol */
            map.put((char) 982, "piv");      /* Greek pi symbol */
            map.put((char) 8194, "ensp");    /* en space */
            map.put((char) 8195, "emsp");    /* em space */
            map.put((char) 8201, "thinsp");  /* thin space */
            map.put((char) 8204, "zwnj");    /* zero width non-joiner */
            map.put((char) 8205, "zwj");     /* zero width joiner */
            map.put((char) 8206, "lrm");     /* left-to-right mark */
            map.put((char) 8207, "rlm");     /* right-to-left mark */
            map.put((char) 8211, "ndash");   /* en dash */
            map.put((char) 8212, "mdash");   /* em dash */
            map.put((char) 8216, "lsquo");   /* left single quotation mark */
            map.put((char) 8217, "rsquo");   /* right single quotation mark */
            map.put((char) 8218, "sbquo");   /* single low-9 quotation mark */
            map.put((char) 8220, "ldquo");   /* left double quotation mark */
            map.put((char) 8221, "rdquo");   /* right double quotation mark */
            map.put((char) 8222, "bdquo");   /* double low-9 quotation mark */
            map.put((char) 8224, "dagger");  /* dagger */
            map.put((char) 8225, "Dagger");  /* double dagger */
            map.put((char) 8226, "bull");    /* bullet */
            map.put((char) 8230, "hellip");  /* horizontal ellipsis */
            map.put((char) 8240, "permil");  /* per mille sign */
            map.put((char) 8242, "prime");   /* prime */
            map.put((char) 8243, "Prime");   /* double prime */
            map.put((char) 8249, "lsaquo");  /* single left-pointing angle quotation mark */
            map.put((char) 8250, "rsaquo");  /* single right-pointing angle quotation mark */
            map.put((char) 8254, "oline");   /* overline */
            map.put((char) 8260, "frasl");   /* fraction slash */
            map.put((char) 8364, "euro");    /* euro sign */
            map.put((char) 8465, "image");   /* black-letter capital i */
            map.put((char) 8472, "weierp");  /* script capital pXCOMMAX Weierstrass p */
            map.put((char) 8476, "real");    /* black-letter capital r */
            map.put((char) 8482, "trade");   /* trademark sign */
            map.put((char) 8501, "alefsym"); /* alef symbol */
            map.put((char) 8592, "larr");    /* leftwards arrow */
            map.put((char) 8593, "uarr");    /* upwards arrow */
            map.put((char) 8594, "rarr");    /* rightwards arrow */
            map.put((char) 8595, "darr");    /* downwards arrow */
            map.put((char) 8596, "harr");    /* left right arrow */
            map.put((char) 8629, "crarr");   /* downwards arrow with corner leftwards */
            map.put((char) 8656, "lArr");    /* leftwards double arrow */
            map.put((char) 8657, "uArr");    /* upwards double arrow */
            map.put((char) 8658, "rArr");    /* rightwards double arrow */
            map.put((char) 8659, "dArr");    /* downwards double arrow */
            map.put((char) 8660, "hArr");    /* left right double arrow */
            map.put((char) 8704, "forall");  /* for all */
            map.put((char) 8706, "part");    /* partial differential */
            map.put((char) 8707, "exist");   /* there exists */
            map.put((char) 8709, "empty");   /* empty set */
            map.put((char) 8711, "nabla");   /* nabla */
            map.put((char) 8712, "isin");    /* element of */
            map.put((char) 8713, "notin");   /* not an element of */
            map.put((char) 8715, "ni");      /* contains as member */
            map.put((char) 8719, "prod");    /* n-ary product */
            map.put((char) 8721, "sum");     /* n-ary summation */
            map.put((char) 8722, "minus");   /* minus sign */
            map.put((char) 8727, "lowast");  /* asterisk operator */
            map.put((char) 8730, "radic");   /* square root */
            map.put((char) 8733, "prop");    /* proportional to */
            map.put((char) 8734, "infin");   /* infinity */
            map.put((char) 8736, "ang");     /* angle */
            map.put((char) 8743, "and");     /* logical and */
            map.put((char) 8744, "or");      /* logical or */
            map.put((char) 8745, "cap");     /* intersection */
            map.put((char) 8746, "cup");     /* union */
            map.put((char) 8747, "int");     /* integral */
            map.put((char) 8756, "there4");  /* therefore */
            map.put((char) 8764, "sim");     /* tilde operator */
            map.put((char) 8773, "cong");    /* congruent to */
            map.put((char) 8776, "asymp");   /* almost equal to */
            map.put((char) 8800, "ne");      /* not equal to */
            map.put((char) 8801, "equiv");   /* identical toXCOMMAX equivalent to */
            map.put((char) 8804, "le");      /* less-than or equal to */
            map.put((char) 8805, "ge");      /* greater-than or equal to */
            map.put((char) 8834, "sub");     /* subset of */
            map.put((char) 8835, "sup");     /* superset of */
            map.put((char) 8836, "nsub");    /* not a subset of */
            map.put((char) 8838, "sube");    /* subset of or equal to */
            map.put((char) 8839, "supe");    /* superset of or equal to */
            map.put((char) 8853, "oplus");   /* circled plus */
            map.put((char) 8855, "otimes");  /* circled times */
            map.put((char) 8869, "perp");    /* up tack */
            map.put((char) 8901, "sdot");    /* dot operator */
            map.put((char) 8968, "lceil");   /* left ceiling */
            map.put((char) 8969, "rceil");   /* right ceiling */
            map.put((char) 8970, "lfloor");  /* left floor */
            map.put((char) 8971, "rfloor");  /* right floor */
            map.put((char) 9001, "lang");    /* left-pointing angle bracket */
            map.put((char) 9002, "rang");    /* right-pointing angle bracket */
            map.put((char) 9674, "loz");     /* lozenge */
            map.put((char) 9824, "spades");  /* black spade suit */
            map.put((char) 9827, "clubs");   /* black club suit */
            map.put((char) 9829, "hearts");  /* black heart suit */
            map.put((char) 9830, "diams");   /* black diamond suit */

            return ImmutableMap.copyOf(map);
        }
    }

}
