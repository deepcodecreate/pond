package com.pond.inspector.ui.screens

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.pond.inspector.PondViewModel
import com.pond.inspector.model.AppLanguage
import com.pond.inspector.model.DensityStyle
import com.pond.inspector.model.IconShapeId
import com.pond.inspector.model.MotionStyle
import com.pond.inspector.model.PaletteStyle
import com.pond.inspector.model.SEED_PRESETS
import com.pond.inspector.model.ThemeMode
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.components.ChoiceFlow
import com.pond.inspector.ui.components.PondCard
import com.pond.inspector.ui.components.PondTopBar
import com.pond.inspector.ui.components.SectionTitle
import com.pond.inspector.ui.components.Segmented
import com.pond.inspector.ui.components.SliderRow
import com.pond.inspector.ui.components.SwitchRow
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.components.withExtra
import com.pond.inspector.ui.localizeDigits
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.theme.iconShape
import com.pond.inspector.ui.theme.seedColorScheme
import com.pond.inspector.ui.tr
import java.util.Locale

@Composable
fun AppearanceScreen(vm: PondViewModel, onBack: () -> Unit) {
    val prefs by vm.appearance.collectAsStateWithLifecycle()
    val a = prefs ?: return
    val pad = LocalPad.current
    val persian = LocalPersian.current
    val haptic = rememberHaptic()
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    val dynamicActive = a.wallpaperColors && Build.VERSION.SDK_INT >= 31
    val hue = FloatArray(3).also { android.graphics.Color.colorToHSV(a.seed, it) }[0]

    fun pct(value: Float): String =
        localizeDigits(String.format(Locale.US, "%d%%", Math.round(value * 100f)), persian)

    fun signed(value: Float): String =
        localizeDigits(String.format(Locale.US, "%+.1f", value), persian)

    Scaffold(
        modifier = Modifier.nestedScroll(scroll.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = { PondTopBar(tr("Appearance", "ظاهر"), scroll, onBack) },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = inner.withExtra(horizontal = pad, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(pad * 0.75f),
        ) {
            item { SchemePreview() }

            item { SectionTitle(tr("Theme", "تم")) }
            item {
                PondCard {
                    Segmented(
                        options = listOf(
                            ThemeMode.System to tr("System", "سیستم"),
                            ThemeMode.Light to tr("Light", "روشن"),
                            ThemeMode.Dark to tr("Dark", "تیره"),
                        ),
                        selected = a.themeMode,
                        onSelect = { value -> vm.updateAppearance { it.copy(themeMode = value) } },
                    )
                    SwitchRow(
                        title = tr("Wallpaper colors", "رنگ‌های والپیپر"),
                        subtitle = if (Build.VERSION.SDK_INT >= 31) {
                            tr("Follow the system dynamic palette", "پیروی از پالت پویای سیستم")
                        } else {
                            tr("Needs Android 12 or newer", "به اندروید ۱۲ یا بالاتر نیاز دارد")
                        },
                        checked = a.wallpaperColors && Build.VERSION.SDK_INT >= 31,
                        enabled = Build.VERSION.SDK_INT >= 31,
                        onChange = { value -> vm.updateAppearance { it.copy(wallpaperColors = value) } },
                        modifier = Modifier.padding(top = 8.dp),
                    )
                    SwitchRow(
                        title = tr("Pure black", "مشکی خالص"),
                        subtitle = tr("Black surfaces in dark theme", "سطوح مشکی در تم تیره"),
                        checked = a.pureBlack,
                        onChange = { value -> vm.updateAppearance { it.copy(pureBlack = value) } },
                    )
                }
            }

            item { SectionTitle(tr("Color", "رنگ")) }
            item {
                PondCard {
                    if (dynamicActive) {
                        Text(
                            tr(
                                "Wallpaper colors are on, so the seed and palette below are not used.",
                                "رنگ‌های والپیپر روشن است، پس رنگ پایه و پالت زیر استفاده نمی‌شوند.",
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                    Column(Modifier.alpha(if (dynamicActive) 0.5f else 1f)) {
                        Text(tr("Seed color", "رنگ پایه"), style = MaterialTheme.typography.bodyLarge)
                        FlowRow(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            val swatchDark = MaterialTheme.colorScheme.background.luminance() < 0.5f
                            SEED_PRESETS.forEach { seed ->
                                val selected = seed == a.seed
                                val swatch = seedColorScheme(Color(seed), swatchDark, a.palette)
                                Box(
                                    Modifier
                                        .size(44.dp)
                                        .clip(iconShape(a.iconShape))
                                        .background(swatch.primary)
                                        .clickable(enabled = !dynamicActive) {
                                            haptic.tap()
                                            vm.updateAppearance { it.copy(seed = seed) }
                                        },
                                    contentAlignment = Alignment.Center,
                                ) {
                                    if (selected) {
                                        Icon(Icons.Rounded.Check, contentDescription = null, tint = swatch.onPrimary)
                                    }
                                }
                            }
                        }
                        SliderRow(
                            title = tr("Custom hue", "طیف دلخواه"),
                            value = hue,
                            range = 0f..360f,
                            format = { localizeDigits(Math.round(it).toString() + "°", persian) },
                            enabled = !dynamicActive,
                            onCommit = { value ->
                                val color = Color.hsv(value, 0.75f, 0.6f).toArgb()
                                vm.updateAppearance { it.copy(seed = color) }
                            },
                        )
                        Text(
                            tr("Palette style", "سبک پالت"),
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(top = 8.dp, bottom = 8.dp),
                        )
                        ChoiceFlow(
                            options = listOf(
                                PaletteStyle.TonalSpot to tr("Tonal spot", "تونال"),
                                PaletteStyle.Vibrant to tr("Vibrant", "پرانرژی"),
                                PaletteStyle.Expressive to tr("Expressive", "اکسپرسیو"),
                                PaletteStyle.Rainbow to tr("Rainbow", "رنگین‌کمان"),
                                PaletteStyle.FruitSalad to tr("Fruit salad", "سالاد میوه"),
                                PaletteStyle.Content to tr("Content", "محتوا"),
                                PaletteStyle.Fidelity to tr("Fidelity", "وفادار"),
                                PaletteStyle.Neutral to tr("Neutral", "خنثی"),
                                PaletteStyle.Monochrome to tr("Monochrome", "تک‌رنگ"),
                            ),
                            selected = a.palette,
                            enabled = !dynamicActive,
                            onSelect = { value -> vm.updateAppearance { it.copy(palette = value) } },
                        )
                    }
                    SliderRow(
                        title = tr("Contrast", "کنتراست"),
                        value = a.contrast,
                        range = -1f..1f,
                        format = ::signed,
                        onCommit = { value -> vm.updateAppearance { it.copy(contrast = value) } },
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }

            item { SectionTitle(tr("Shape and size", "شکل و اندازه")) }
            item {
                PondCard {
                    SliderRow(
                        title = tr("Corner roundness", "گردی گوشه‌ها"),
                        value = a.cornerScale,
                        range = 0.4f..1.6f,
                        format = ::pct,
                        onCommit = { value -> vm.updateAppearance { it.copy(cornerScale = value) } },
                    )
                    SliderRow(
                        title = tr("Text size", "اندازهٔ متن"),
                        value = a.textScale,
                        range = 0.8f..1.4f,
                        format = ::pct,
                        onCommit = { value -> vm.updateAppearance { it.copy(textScale = value) } },
                    )
                    Text(
                        tr("Icon shape", "شکل آیکون"),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(start = 4.dp, top = 12.dp, bottom = 8.dp),
                    )
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        IconShapeId.entries.forEach { id ->
                            val selected = id == a.iconShape
                            Box(
                                Modifier
                                    .size(52.dp)
                                    .clip(iconShape(id))
                                    .background(
                                        if (selected) {
                                            MaterialTheme.colorScheme.primary
                                        } else {
                                            MaterialTheme.colorScheme.surfaceContainerHighest
                                        },
                                    )
                                    .clickable {
                                        haptic.tap()
                                        vm.updateAppearance { it.copy(iconShape = id) }
                                    },
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    Icons.Rounded.Shield,
                                    contentDescription = null,
                                    modifier = Modifier.size(24.dp),
                                    tint = if (selected) {
                                        MaterialTheme.colorScheme.onPrimary
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            }
                        }
                    }
                    Text(
                        tr("Layout density", "تراکم چیدمان"),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 8.dp),
                    )
                    Segmented(
                        options = listOf(
                            DensityStyle.Comfortable to tr("Comfortable", "راحت"),
                            DensityStyle.Compact to tr("Compact", "فشرده"),
                        ),
                        selected = a.density,
                        onSelect = { value -> vm.updateAppearance { it.copy(density = value) } },
                    )
                }
            }

            item { SectionTitle(tr("Motion and feedback", "حرکت و بازخورد")) }
            item {
                PondCard {
                    Segmented(
                        options = listOf(
                            MotionStyle.Expressive to tr("Expressive", "اکسپرسیو"),
                            MotionStyle.Standard to tr("Standard", "استاندارد"),
                            MotionStyle.Reduced to tr("Reduced", "کم"),
                        ),
                        selected = a.motion,
                        onSelect = { value -> vm.updateAppearance { it.copy(motion = value) } },
                    )
                    SwitchRow(
                        title = tr("Haptic feedback", "بازخورد لمسی"),
                        checked = a.haptics,
                        onChange = { value -> vm.updateAppearance { it.copy(haptics = value) } },
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            }

            item { SectionTitle(tr("Language", "زبان")) }
            item {
                PondCard {
                    Segmented(
                        options = listOf(
                            AppLanguage.System to tr("System", "سیستم"),
                            AppLanguage.English to "English",
                            AppLanguage.Persian to "فارسی",
                        ),
                        selected = a.language,
                        onSelect = { value -> vm.updateAppearance { it.copy(language = value) } },
                    )
                }
            }

            item { SectionTitle(tr("Details", "جزئیات")) }
            item {
                PondCard {
                    SwitchRow(
                        title = tr("Show raw details", "نمایش جزئیات خام"),
                        subtitle = tr(
                            "Status code and timing on each check",
                            "کد وضعیت و زمان اجرا در هر بررسی",
                        ),
                        checked = a.showRaw,
                        onChange = { value -> vm.updateAppearance { it.copy(showRaw = value) } },
                    )
                }
            }

            item {
                FilledTonalButton(
                    onClick = {
                        haptic.confirm()
                        vm.resetAppearance()
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Rounded.RestartAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text(
                        tr("Reset appearance", "بازنشانی ظاهر"),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun SchemePreview() {
    val c = MaterialTheme.colorScheme
    PondCard(container = c.surfaceContainerHigh) {
        Text(tr("Preview", "پیش‌نمایش"), style = MaterialTheme.typography.titleSmall, color = c.primary)
        Row(
            Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            listOf(
                c.primary,
                c.primaryContainer,
                c.secondary,
                c.secondaryContainer,
                c.tertiary,
                c.tertiaryContainer,
                c.error,
            ).forEach { color ->
                Box(
                    Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(color),
                )
            }
        }
    }
}
