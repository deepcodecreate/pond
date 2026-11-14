package com.pond.inspector.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import com.pond.inspector.model.PaletteStyle
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

private data class Spec(
    val sat: Float,
    val secondaryShift: Float,
    val tertiaryShift: Float,
)

private fun PaletteStyle.spec(seedSat: Float): Spec = when (this) {
    PaletteStyle.TonalSpot -> Spec(0.62f, 22f, 52f)
    PaletteStyle.Vibrant -> Spec(0.92f, 36f, 168f)
    PaletteStyle.Expressive -> Spec(0.78f, 30f, 64f)
    PaletteStyle.Rainbow -> Spec(0.82f, 120f, 240f)
    PaletteStyle.FruitSalad -> Spec(0.72f, 32f, 128f)
    PaletteStyle.Content -> Spec(seedSat.coerceIn(0.22f, 0.5f), 14f, 30f)
    PaletteStyle.Fidelity -> Spec(seedSat.coerceIn(0.25f, 0.95f), 8f, 16f)
    PaletteStyle.Neutral -> Spec(0.1f, 0f, 0f)
    PaletteStyle.Monochrome -> Spec(0f, 0f, 0f)
}

private fun hsv(h: Float, s: Float, v: Float): Color {
    val hue = ((h % 360f) + 360f) % 360f
    return Color(
        android.graphics.Color.HSVToColor(
            floatArrayOf(hue, s.coerceIn(0f, 1f), v.coerceIn(0f, 1f)),
        ),
    )
}

private fun harmonized(argb: Long, hue: Float, amount: Float): Color {
    val base = Color(argb.toInt())
    val target = hsv(hue, 0.5f, 0.5f)
    return lerp(base, target, amount).copy(alpha = 1f)
}

fun seedColorScheme(seed: Color, dark: Boolean, style: PaletteStyle): ColorScheme {
    val hsv = FloatArray(3)
    android.graphics.Color.colorToHSV(seed.toArgb(), hsv)
    val hue = hsv[0]
    val spec = style.spec(hsv[1])
    val p = hue
    val s = hue + spec.secondaryShift
    val t = hue + spec.tertiaryShift
    val sat = spec.sat
    return if (dark) {
        darkColorScheme(
            primary = hsv(p, sat * 0.72f, 0.92f),
            onPrimary = hsv(p, sat, 0.18f),
            primaryContainer = hsv(p, sat * 0.55f, 0.30f),
            onPrimaryContainer = hsv(p, sat * 0.35f, 0.95f),
            secondary = hsv(s, sat * 0.5f, 0.88f),
            onSecondary = hsv(s, sat * 0.6f, 0.16f),
            secondaryContainer = hsv(s, sat * 0.35f, 0.26f),
            onSecondaryContainer = hsv(s, sat * 0.25f, 0.94f),
            tertiary = hsv(t, sat * 0.62f, 0.90f),
            onTertiary = hsv(t, sat * 0.7f, 0.16f),
            tertiaryContainer = hsv(t, sat * 0.4f, 0.26f),
            onTertiaryContainer = hsv(t, sat * 0.28f, 0.95f),
            background = hsv(hue, 0.08f, 0.07f),
            onBackground = hsv(hue, 0.04f, 0.94f),
            surface = hsv(hue, 0.08f, 0.07f),
            onSurface = hsv(hue, 0.04f, 0.94f),
            surfaceVariant = hsv(hue, 0.07f, 0.18f),
            onSurfaceVariant = hsv(hue, 0.05f, 0.78f),
            surfaceTint = hsv(p, sat * 0.72f, 0.92f),
            outline = hsv(hue, 0.05f, 0.55f),
            outlineVariant = hsv(hue, 0.06f, 0.28f),
            surfaceContainerLowest = hsv(hue, 0.06f, 0.05f),
            surfaceContainerLow = hsv(hue, 0.07f, 0.10f),
            surfaceContainer = hsv(hue, 0.07f, 0.14f),
            surfaceContainerHigh = hsv(hue, 0.06f, 0.18f),
            surfaceContainerHighest = hsv(hue, 0.05f, 0.23f),
            surfaceDim = hsv(hue, 0.08f, 0.07f),
            surfaceBright = hsv(hue, 0.05f, 0.27f),
            inverseSurface = hsv(hue, 0.05f, 0.90f),
            inverseOnSurface = hsv(hue, 0.08f, 0.16f),
            inversePrimary = hsv(p, sat * 0.78f, 0.40f),
            error = harmonized(0xFFFFB4AB, hue, 0.10f),
            onError = harmonized(0xFF690005, hue, 0.10f),
            errorContainer = harmonized(0xFF93000A, hue, 0.10f),
            onErrorContainer = harmonized(0xFFFFDAD6, hue, 0.10f),
            scrim = Color.Black,
        )
    } else {
        lightColorScheme(
            primary = hsv(p, sat * 0.78f, 0.40f),
            onPrimary = Color.White,
            primaryContainer = hsv(p, sat * 0.32f, 0.92f),
            onPrimaryContainer = hsv(p, sat * 0.7f, 0.20f),
            secondary = hsv(s, sat * 0.45f, 0.38f),
            onSecondary = Color.White,
            secondaryContainer = hsv(s, sat * 0.22f, 0.93f),
            onSecondaryContainer = hsv(s, sat * 0.4f, 0.20f),
            tertiary = hsv(t, sat * 0.5f, 0.38f),
            onTertiary = Color.White,
            tertiaryContainer = hsv(t, sat * 0.24f, 0.93f),
            onTertiaryContainer = hsv(t, sat * 0.45f, 0.18f),
            background = hsv(hue, 0.05f, 0.985f),
            onBackground = hsv(hue, 0.08f, 0.12f),
            surface = hsv(hue, 0.05f, 0.985f),
            onSurface = hsv(hue, 0.08f, 0.12f),
            surfaceVariant = hsv(hue, 0.06f, 0.92f),
            onSurfaceVariant = hsv(hue, 0.06f, 0.32f),
            surfaceTint = hsv(p, sat * 0.78f, 0.40f),
            outline = hsv(hue, 0.05f, 0.48f),
            outlineVariant = hsv(hue, 0.05f, 0.82f),
            surfaceContainerLowest = Color.White,
            surfaceContainerLow = hsv(hue, 0.04f, 0.97f),
            surfaceContainer = hsv(hue, 0.05f, 0.95f),
            surfaceContainerHigh = hsv(hue, 0.05f, 0.93f),
            surfaceContainerHighest = hsv(hue, 0.06f, 0.90f),
            surfaceDim = hsv(hue, 0.06f, 0.87f),
            surfaceBright = hsv(hue, 0.05f, 0.985f),
            inverseSurface = hsv(hue, 0.08f, 0.20f),
            inverseOnSurface = hsv(hue, 0.04f, 0.95f),
            inversePrimary = hsv(p, sat * 0.72f, 0.92f),
            error = harmonized(0xFFB3261E, hue, 0.10f),
            onError = Color.White,
            errorContainer = harmonized(0xFFF9DEDC, hue, 0.10f),
            onErrorContainer = harmonized(0xFF410E0B, hue, 0.10f),
            scrim = Color.Black,
        )
    }
}

private fun ratio(a: Color, b: Color): Float {
    val l1 = a.luminance()
    val l2 = b.luminance()
    return (max(l1, l2) + 0.05f) / (min(l1, l2) + 0.05f)
}

private fun Color.readableOn(bg: Color, minRatio: Float = 4.5f): Color {
    if (ratio(this, bg) >= minRatio) return this
    val dark = Color(0xFF101114)
    val light = Color(0xFFFAFAFC)
    return if (ratio(dark, bg) >= ratio(light, bg)) dark else light
}

fun ColorScheme.tuned(contrast: Float, pureBlack: Boolean): ColorScheme {
    val amount = contrast.coerceIn(-1f, 1f)
    val isDark = background.luminance() < 0.5f
    val extreme = if (isDark) Color.White else Color.Black
    fun Color.push(): Color {
        if (abs(amount) < 0.02f) return this
        return if (amount > 0f) {
            lerp(this, extreme, amount * 0.35f)
        } else {
            lerp(this, surface, -amount * 0.35f)
        }
    }
    fun Color.pushText(): Color {
        if (amount < 0.02f) return this
        return lerp(this, extreme, amount * 0.45f)
    }
    var out = copy(
        primary = primary.push(),
        secondary = secondary.push(),
        tertiary = tertiary.push(),
        primaryContainer = primaryContainer.push(),
        secondaryContainer = secondaryContainer.push(),
        tertiaryContainer = tertiaryContainer.push(),
        onSurfaceVariant = onSurfaceVariant.pushText(),
        outline = outline.pushText(),
        outlineVariant = outlineVariant.pushText(),
    )
    if (pureBlack) {
        out = out.copy(
            background = Color.Black,
            surface = Color.Black,
            surfaceDim = Color.Black,
            surfaceContainerLowest = Color.Black,
            surfaceContainerLow = Color(0xFF0A0A0A),
            surfaceContainer = Color(0xFF111111),
            surfaceContainerHigh = Color(0xFF191919),
            surfaceContainerHighest = Color(0xFF222222),
            surfaceBright = Color(0xFF2C2C2C),
        )
    }
    return out.copy(
        onPrimary = out.onPrimary.readableOn(out.primary),
        onSecondary = out.onSecondary.readableOn(out.secondary),
        onTertiary = out.onTertiary.readableOn(out.tertiary),
        onPrimaryContainer = out.onPrimaryContainer.readableOn(out.primaryContainer),
        onSecondaryContainer = out.onSecondaryContainer.readableOn(out.secondaryContainer),
        onTertiaryContainer = out.onTertiaryContainer.readableOn(out.tertiaryContainer),
        onError = out.onError.readableOn(out.error),
        onErrorContainer = out.onErrorContainer.readableOn(out.errorContainer),
        onBackground = out.onBackground.readableOn(out.background),
        onSurface = out.onSurface.readableOn(out.surface),
        onSurfaceVariant = out.onSurfaceVariant.readableOn(out.surfaceContainerHighest),
        inverseOnSurface = out.inverseOnSurface.readableOn(out.inverseSurface),
    )
}
