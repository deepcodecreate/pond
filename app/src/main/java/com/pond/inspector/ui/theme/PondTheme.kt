package com.pond.inspector.ui.theme

import android.app.Activity
import android.graphics.drawable.ColorDrawable
import android.os.Build
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Matrix
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.hapticfeedback.HapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.graphics.shapes.CornerRounding
import androidx.graphics.shapes.Cubic
import androidx.graphics.shapes.Morph
import androidx.graphics.shapes.RoundedPolygon
import androidx.graphics.shapes.star
import com.pond.inspector.model.AppearancePrefs
import com.pond.inspector.model.IconShapeId
import com.pond.inspector.model.Status
import com.pond.inspector.model.ThemeMode
import kotlinx.coroutines.isActive
import kotlin.math.min

private object SilentHaptics : HapticFeedback {
    override fun performHapticFeedback(hapticFeedbackType: HapticFeedbackType) = Unit
}

fun pondShapes(scale: Float): Shapes {
    fun r(dp: Int) = RoundedCornerShape((dp * scale).coerceAtLeast(2f).dp)
    return Shapes(
        extraSmall = r(8),
        small = r(12),
        medium = r(16),
        large = r(24),
        extraLarge = r(32),
    )
}

private fun List<Cubic>.toComposePath(): Path {
    val path = Path()
    val first = firstOrNull() ?: return path
    path.moveTo(first.anchor0X, first.anchor0Y)
    forEach { path.cubicTo(it.control0X, it.control0Y, it.control1X, it.control1Y, it.anchor1X, it.anchor1Y) }
    path.close()
    return path
}

private val polygons: Map<IconShapeId, RoundedPolygon> by lazy {
    mapOf(
        IconShapeId.Cookie4 to RoundedPolygon.star(4, innerRadius = 0.78f, rounding = CornerRounding(0.4f), innerRounding = CornerRounding(0.4f)),
        IconShapeId.Clover4 to RoundedPolygon.star(4, innerRadius = 0.42f, rounding = CornerRounding(0.5f), innerRounding = CornerRounding(0.2f)),
        IconShapeId.Sunny to RoundedPolygon.star(8, innerRadius = 0.8f, rounding = CornerRounding(0.15f), innerRounding = CornerRounding(0.15f)),
        IconShapeId.Gem to RoundedPolygon(6, rounding = CornerRounding(0.18f)),
        IconShapeId.Puffy to RoundedPolygon.star(10, innerRadius = 0.78f, rounding = CornerRounding(0.6f), innerRounding = CornerRounding(0.6f)),
        IconShapeId.Arch to RoundedPolygon(4, rounding = CornerRounding(0.5f)),
        IconShapeId.SoftBurst to RoundedPolygon.star(10, innerRadius = 0.86f, rounding = CornerRounding(0.25f), innerRounding = CornerRounding(0.25f)),
        IconShapeId.Flower to RoundedPolygon.star(6, innerRadius = 0.62f, rounding = CornerRounding(0.5f), innerRounding = CornerRounding(0.5f)),
    ).mapValues { it.value.normalized() }
}

private class PolygonShape(private val polygon: RoundedPolygon) : Shape {
    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density): Outline {
        val path = polygon.cubics.toComposePath()
        path.transform(Matrix().apply { scale(size.width, size.height) })
        return Outline.Generic(path)
    }
}

@Composable
fun iconShape(id: IconShapeId): Shape = remember(id) { PolygonShape(polygons.getValue(id)) }

@Composable
fun PondTheme(appearance: AppearancePrefs, content: @Composable () -> Unit) {
    val context = LocalContext.current
    val dark = when (appearance.themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
    val scheme = remember(
        appearance.seed,
        appearance.palette,
        appearance.contrast,
        appearance.pureBlack,
        appearance.wallpaperColors,
        dark,
    ) {
        val base: ColorScheme = if (appearance.wallpaperColors && Build.VERSION.SDK_INT >= 31) {
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        } else {
            seedColorScheme(Color(appearance.seed), dark, appearance.palette)
        }
        base.tuned(appearance.contrast, appearance.pureBlack && dark)
    }
    val shapes = remember(appearance.cornerScale) { pondShapes(appearance.cornerScale) }
    val baseDensity = LocalDensity.current
    val density = remember(baseDensity, appearance.textScale) {
        Density(baseDensity.density, baseDensity.fontScale * appearance.textScale)
    }
    val haptics = LocalHapticFeedback.current
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = !dark
            controller.isAppearanceLightNavigationBars = !dark
            window.setBackgroundDrawable(ColorDrawable(scheme.background.toArgb()))
            window.isNavigationBarContrastEnforced = false
        }
    }
    MaterialTheme(colorScheme = scheme, shapes = shapes) {
        CompositionLocalProvider(
            LocalDensity provides density,
            LocalHapticFeedback provides if (appearance.haptics) haptics else SilentHaptics,
            content = content,
        )
    }
}

@Composable
fun PondMark(
    scanning: Boolean,
    reduced: Boolean,
    modifier: Modifier = Modifier,
    description: String = "",
) {
    val morph = remember {
        Morph(
            polygons.getValue(IconShapeId.Cookie4),
            polygons.getValue(IconShapeId.Sunny),
        )
    }
    val progress = remember { Animatable(0.22f) }
    LaunchedEffect(scanning, reduced) {
        if (!scanning || reduced) {
            progress.animateTo(0.22f, tween(300))
            return@LaunchedEffect
        }
        while (isActive) {
            progress.animateTo(1f, tween(900))
            progress.animateTo(0f, tween(900))
        }
    }
    val color = LocalContentColor.current
    Canvas(
        modifier
            .size(72.dp)
            .semantics { if (description.isNotEmpty()) contentDescription = description },
    ) {
        val raw = morph.asCubics(progress.value.coerceIn(0f, 1f)).toComposePath()
        val bounds = raw.getBounds()
        if (bounds.width <= 0f || bounds.height <= 0f) return@Canvas
        val scale = min(size.width / bounds.width, size.height / bounds.height) * 0.92f
        val transformed = Path().apply {
            addPath(raw)
            transform(
                Matrix().apply {
                    translate(size.width / 2f, size.height / 2f)
                    scale(scale, scale)
                    translate(-bounds.center.x, -bounds.center.y)
                },
            )
        }
        drawPath(transformed, color)
    }
}

private fun harmonizeHue(base: Float, target: Float): Float {
    val d = ((target - base + 540f) % 360f) - 180f
    val shift = (d * 0.5f).coerceIn(-15f, 15f)
    return (base + shift + 360f) % 360f
}

@Composable
fun statusColors(status: Status): Pair<Color, Color> {
    val scheme = MaterialTheme.colorScheme
    val dark = scheme.background.luminance() < 0.5f
    val primaryHsv = FloatArray(3)
    android.graphics.Color.colorToHSV(scheme.primary.toArgb(), primaryHsv)
    fun tonal(baseHue: Float): Pair<Color, Color> {
        val h = harmonizeHue(baseHue, primaryHsv[0])
        return if (dark) {
            Color.hsv(h, 0.34f, 0.96f) to Color.hsv(h, 0.62f, 0.27f)
        } else {
            Color.hsv(h, 0.88f, 0.30f) to Color.hsv(h, 0.17f, 0.96f)
        }
    }
    return when (status) {
        Status.CLEAR -> tonal(145f)
        Status.WARNING -> tonal(38f)
        Status.DANGER, Status.ERROR -> tonal(4f)
        Status.INFO -> scheme.onPrimaryContainer to scheme.primaryContainer
        Status.PENDING, Status.UNSUPPORTED -> scheme.onSurfaceVariant to scheme.surfaceContainerHighest
    }
}

fun Modifier.clipToIcon(shape: Shape): Modifier = clip(shape)
