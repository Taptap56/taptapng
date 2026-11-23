package com.taptap.ng

import java.io.File
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression test for the v1.0.24 phone report (screenshot
 * 2026-11-24 04:33, dialog "Tambah grup"): the labels
 * "URL tes (URL-TEST)" and "Interval tes (detik, 60-3600)"
 * OVERLAPPED their values ("http://www.gstatic.com/generate_204"
 * and "300") — neither the label nor the value was readable.
 * "Nama grup" (empty when adding), "Tipe grup" and
 * "Anggota terpilih (SELECT)" were fine.
 *
 * Root cause, from the code (GroupsActivity.showGroupDialog):
 * the label of both fields existed ONLY as `EditText.hint`
 * (a hint renders inside the text area, at the value's place),
 * inside a bare `TextInputLayout(ctx)` — no hint on the layout
 * itself, no OutlinedBox style, plain `EditText` instead of
 * `TextInputEditText`. The floating label that would lift the
 * hint above the value was never established by the code, and
 * Google's own TextInputLayout doc says the hint belongs on the
 * layout: a hint on the child EditText only "might still work
 * correctly". Both fields are ALWAYS pre-filled at construction
 * (default URL tes / default interval), so from the first frame
 * hint and value shared the same text area. "Nama grup" uses the
 * identical hint-only pattern but is empty for a new group, so
 * its hint shows alone as a placeholder and the defect is
 * invisible there. The server editor already knew this failure
 * class: its header comment records a hint inside the box being
 * removed because it doubled/overlapped with the label, and its
 * fields put `android:hint` on an OutlinedBox TextInputLayout.
 *
 * v1.0.25 fix: label both fields with the same `labeled()`
 * helper the spinners in this very dialog already use — a real
 * TextView label ABOVE the field in a vertical LinearLayout, so
 * overlapping is structurally impossible — and drop the
 * `EditText.hint` on both fields. Same strings, same pre-filled
 * defaults, same input types; nothing else in the dialog moves.
 *
 * Source assertions only: visual readability cannot be tested on
 * the JVM (no Robolectric in this tree) — the deciding proof is
 * the phone screenshot. If anyone reverts any part of the fix,
 * a test here fails.
 */
class GroupDialogLabelsTest {

    private fun projectRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "app/src/main/res/layout/activity_groups.xml").exists()) return dir
            dir = dir.parentFile
        }
        error("project root not found from user.dir=${System.getProperty("user.dir")}")
    }

    private fun read(rel: String): String {
        val f = File(projectRoot(), rel)
        assertTrue(f.exists(), "$rel must exist")
        return f.readText()
    }

    private fun src(): String =
        read("app/src/main/java/com/taptap/ng/ui/groups/GroupsActivity.kt")

    /** The block of one dialog field, from its `val` to the next field. */
    private fun fieldBlock(source: String, from: String, until: String): String =
        source.substringAfter(from).substringBefore(until)

    @Test
    fun `url test and interval fields are labeled above the field, not by EditText hint`() {
        val source = src()
        // Neither field may carry its label as an EditText hint
        // anymore: a hint renders inside the text area, on top of
        // the pre-filled value (the v1.0.24 overlap).
        assertFalse(
            source.contains("hint = getString(R.string.groups_url_test_url)"),
            "urlInput must not set EditText.hint to the URL-tes label " +
                "(hint + pre-filled value overlap in the same text area)",
        )
        assertFalse(
            source.contains("hint = getString(R.string.groups_url_test_interval)"),
            "intervalInput must not set EditText.hint to the interval label " +
                "(hint + pre-filled value overlap in the same text area)",
        )
        // Each field is wrapped in labeled() with its own string,
        // the TextInputLayout being the labeled view — the label
        // TextView sits above the field.
        val urlBlock = fieldBlock(source, "val urlInput", "val intervalInput")
        assertTrue(
            urlBlock.contains("labeled(") &&
                urlBlock.contains("getString(R.string.groups_url_test_url)") &&
                urlBlock.contains("TextInputLayout(ctx).apply { addView(urlInput) }"),
            "urlInput must be wrapped in labeled() with the URL-tes string " +
                "and its TextInputLayout as the labeled view",
        )
        assertTrue(
            urlBlock.indexOf("labeled(") < urlBlock.indexOf("TextInputLayout(ctx)"),
            "the labeled() call must wrap the urlInput TextInputLayout",
        )
        val intervalBlock = fieldBlock(source, "val intervalInput", "// Member picking")
        assertTrue(
            intervalBlock.contains("labeled(") &&
                intervalBlock.contains("getString(R.string.groups_url_test_interval)") &&
                intervalBlock.contains("TextInputLayout(ctx).apply { addView(intervalInput) }"),
            "intervalInput must be wrapped in labeled() with the interval string " +
                "and its TextInputLayout as the labeled view",
        )
        assertTrue(
            intervalBlock.indexOf("labeled(") < intervalBlock.indexOf("TextInputLayout(ctx)"),
            "the labeled() call must wrap the intervalInput TextInputLayout",
        )
    }

    @Test
    fun `pre-filled default values are kept`() {
        val source = src()
        val urlBlock = fieldBlock(source, "val urlInput", "val intervalInput")
        assertTrue(
            urlBlock.contains("setText(existing?.urlTestUrl ?: ProxyGroup.DEFAULT_URL_TEST_URL)"),
            "urlInput must still be pre-filled with the stored URL or the default test URL",
        )
        assertTrue(
            urlBlock.contains("InputType.TYPE_TEXT_VARIATION_URI"),
            "urlInput must keep its URI input type",
        )
        val intervalBlock = fieldBlock(source, "val intervalInput", "// Member picking")
        assertTrue(
            intervalBlock.contains(
                "setText((existing?.urlTestIntervalSec ?: " +
                    "ProxyGroup.DEFAULT_URL_TEST_INTERVAL_SEC).toString())",
            ),
            "intervalInput must still be pre-filled with the stored interval or the default",
        )
        assertTrue(
            intervalBlock.contains("InputType.TYPE_CLASS_NUMBER"),
            "intervalInput must keep its numeric input type",
        )
    }

    @Test
    fun `labeled helper puts the label TextView above the field view`() {
        // Guard the helper this fix relies on: if labeled() ever
        // stops adding the label first, the "label above" claim
        // stops being true and this test says so.
        val source = src()
        val helper = source.substringAfter("private fun labeled(")
        assertTrue(
            helper.contains("addView(TextView(ctx).apply {"),
            "labeled() must add a TextView label",
        )
        assertTrue(
            helper.contains("addView(view)"),
            "labeled() must add the field view",
        )
        assertTrue(
            helper.indexOf("addView(TextView(ctx).apply {") < helper.indexOf("addView(view)"),
            "labeled() must add the label TextView BEFORE the field view " +
                "(vertical layout: label above, field below)",
        )
    }

    @Test
    fun `untouched dialog rows keep their shape`() {
        // Surgical scope: only the two URL-tes/interval fields
        // change. Nama grup, Tipe grup, Anggota terpilih, the
        // ANGGOTA button and the OK/Cancel wiring stay as they were.
        val source = src()
        val nameBlock = fieldBlock(source, "val nameInput", "val typeSpinner")
        assertTrue(
            nameBlock.contains("hint = getString(R.string.groups_group_name)"),
            "nameInput must keep its hint (empty for a new group, no overlap)",
        )
        assertTrue(
            nameBlock.contains("root.addView(TextInputLayout(ctx).apply { addView(nameInput) })"),
            "nameInput must stay a plain TextInputLayout row (not wrapped in labeled)",
        )
        assertTrue(
            source.contains(
                "root.addView(labeled(ctx, getString(R.string.groups_group_type), typeSpinner))",
            ),
            "typeSpinner must stay labeled() as before",
        )
        assertTrue(
            source.contains("root.addView(membersButton)"),
            "the ANGGOTA members button must stay",
        )
        assertTrue(
            source.contains("val row = labeled(ctx, getString(R.string.groups_selected), spinner)"),
            "the SELECT chosen-member spinner must stay labeled() as before",
        )
        assertTrue(
            source.contains(".setPositiveButton(android.R.string.ok)"),
            "the dialog OK button wiring must stay",
        )
        assertTrue(
            source.contains(".setNegativeButton(android.R.string.cancel, null)"),
            "the dialog BATAL button wiring must stay",
        )
        // The label strings themselves are unchanged.
        val strings = read("app/src/main/res/values/strings.xml")
        assertTrue(
            strings.contains("<string name=\"groups_url_test_url\">URL tes (URL-TEST)</string>"),
            "groups_url_test_url string must stay unchanged",
        )
        assertTrue(
            strings.contains("<string name=\"groups_url_test_interval\">Interval tes (detik, 60-3600)</string>"),
            "groups_url_test_interval string must stay unchanged",
        )
    }
}
