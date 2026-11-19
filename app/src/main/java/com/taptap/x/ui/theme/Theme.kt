package com.taptap.x.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * Material 3 theme mirroring v2rayNG's Theme.kt (same palette, same
 * structure): black primary, orange secondary (#f97910), green tertiary
 * (#009966). The user asked the UI to look exactly like v2rayNG, so the
 * color scheme is copied 1:1 (light + dark).
 */

// Light scheme (v2rayNG LightColor).
private val LightColor = lightColorScheme(
    primary = Color(0xFF000000),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE0E0E0),
    onPrimaryContainer = Color(0xFF000000),
    secondary = Color(0xFFf97910),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFFFE8D6),
    onSecondaryContainer = Color(0xFF2B1700),
    tertiary = Color(0xFF009966),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFA0F2D0),
    onTertiaryContainer = Color(0xFF00201A),
    error = Color(0xFFBA1A1A),
    errorContainer = Color(0xFFFFDAD6),
    onError = Color(0xFFFFFFFF),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFFFFFFF),
    onBackground = Color(0xFF1C1B1F),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1C1B1F),
    surfaceVariant = Color(0xFFE7E0EC),
    onSurfaceVariant = Color(0xFF49454F),
    outline = Color(0xFF79747E),
    outlineVariant = Color(0xFFCAC4D0),
    inverseSurface = Color(0xFF313033),
    inverseOnSurface = Color(0xFFF4EFF4),
    inversePrimary = Color(0xFFC0C0C0),
    scrim = Color(0xFF000000),
    surfaceTint = Color(0xFF000000),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF7F7F7),
    surfaceContainer = Color(0xFFF1F1F1),
    surfaceContainerHigh = Color(0xFFEBEBEB),
    surfaceContainerHighest = Color(0xFFE5E5E5),
)

// Dark scheme (v2rayNG DarkColor).
private val DarkColor = darkColorScheme(
    primary = Color(0xFFC0C0C0),
    onPrimary = Color(0xFF303030),
    primaryContainer = Color(0xFF474747),
    onPrimaryContainer = Color(0xFFE0E0E0),
    secondary = Color(0xFFf97910),
    onSecondary = Color(0xFF4E2600),
    secondaryContainer = Color(0xFF6F3800),
    onSecondaryContainer = Color(0xFFFFE8D6),
    tertiary = Color(0xFF83D6B5),
    onTertiary = Color(0xFF00382E),
    tertiaryContainer = Color(0xFF005143),
    onTertiaryContainer = Color(0xFFA0F2D0),
    error = Color(0xFFFFB4AB),
    errorContainer = Color(0xFF93000A),
    onError = Color(0xFF690005),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF1C1B1F),
    onBackground = Color(0xFFE6E1E5),
    surface = Color(0xFF1C1B1F),
    onSurface = Color(0xFFE6E1E5),
    surfaceVariant = Color(0xFF49454F),
    onSurfaceVariant = Color(0xFFCAC4D0),
    outline = Color(0xFF938F99),
    outlineVariant = Color(0xFF49454F),
    inverseSurface = Color(0xFFE6E1E5),
    inverseOnSurface = Color(0xFF1C1B1F),
    inversePrimary = Color(0xFF000000),
    scrim = Color(0xFF000000),
    surfaceTint = Color(0xFFC0C0C0),
    surfaceContainerLowest = Color(0xFF0F0F12),
    surfaceContainerLow = Color(0xFF1A191D),
    surfaceContainer = Color(0xFF1E1D21),
    surfaceContainerHigh = Color(0xFF282729),
    surfaceContainerHighest = Color(0xFF333234),
)

// Semantic colors (v2rayNG).
val colorPing = Color(0xFF009966)
val colorPingRed = Color(0xFFFF0099)
val colorConfigType = Color(0xFFf97910)
val colorFabActive = Color(0xFFf97910)
val colorFabInactiveLight = Color(0xFF9C9C9C)
val colorFabInactiveDark = Color(0xFF646464)
val dividerColorLight = Color(0xFFE0E0E0)
val dividerColorDark = Color(0xFF424242)

@Composable
fun TaptapXTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColor else LightColor
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
