package com.pond.inspector.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.graphics.graphicsLayer
import com.pond.inspector.ui.LocalReduced
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.IconButtonColors
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.SwitchColors
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.pond.inspector.logic.displayValue
import com.pond.inspector.model.Evidence
import com.pond.inspector.model.IconShapeId
import com.pond.inspector.model.Status
import com.pond.inspector.ui.LocalIconShape
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalPersian
import com.pond.inspector.ui.statusIcon
import com.pond.inspector.ui.statusLabel
import com.pond.inspector.ui.theme.iconShape
import com.pond.inspector.ui.theme.statusColors

class Haptic(private val feedback: HapticFeedback) {
    fun tap() = feedback.performHapticFeedback(HapticFeedbackType.ContextClick)
    fun toggle(on: Boolean) = feedback.performHapticFeedback(
        if (on) HapticFeedbackType.ToggleOn else HapticFeedbackType.ToggleOff,
    )
    fun confirm() = feedback.performHapticFeedback(HapticFeedbackType.Confirm)
}

@Composable
fun rememberHaptic(): Haptic {
    val feedback = LocalHapticFeedback.current
    return remember(feedback) { Haptic(feedback) }
}

@Composable
fun PondCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    container: Color = MaterialTheme.colorScheme.surfaceContainer,
    outlined: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    val pad = LocalPad.current
    val haptic = rememberHaptic()
    val reduced = LocalReduced.current
    val shape = MaterialTheme.shapes.large
    val colors = CardDefaults.cardColors(containerColor = container)
    val border = if (outlined) {
        BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f))
    } else {
        null
    }
    if (onClick == null) {
        Card(
            modifier = if (reduced) modifier else modifier.animateContentSize(spring(dampingRatio = 0.85f, stiffness = Spring.StiffnessMediumLow)),
            shape = shape, colors = colors, border = border,
        ) {
            Column(Modifier.padding(pad), content = content)
        }
    } else {
        val source = remember { MutableInteractionSource() }
        val pressed by source.collectIsPressedAsState()
        val scale by animateFloatAsState(
            targetValue = if (pressed && !reduced) 0.965f else 1f,
            animationSpec = spring(dampingRatio = 0.6f, stiffness = Spring.StiffnessMedium),
            label = "cardPress",
        )
        Card(
            onClick = {
                haptic.tap()
                onClick()
            },
            modifier = modifier.graphicsLayer {
                scaleX = scale
                scaleY = scale
            },
            shape = shape,
            colors = colors,
            border = border,
            interactionSource = source,
        ) {
            Column(Modifier.padding(pad), content = content)
        }
    }
}

@Composable
fun Modifier.appear(seen: MutableSet<Any>, key: Any, order: Int): Modifier {
    val reduced = LocalReduced.current
    val first = remember(key) { seen.add(key) }
    val animate = first && !reduced
    val progress = remember(key) { Animatable(if (animate) 0f else 1f) }
    if (animate) {
        LaunchedEffect(key) {
            progress.animateTo(
                1f,
                tween(420, delayMillis = order.coerceIn(0, 8) * 45, easing = FastOutSlowInEasing),
            )
        }
    }
    return graphicsLayer {
        alpha = progress.value
        translationY = (1f - progress.value) * 56f
    }
}

@Composable
fun ShapeIcon(
    icon: ImageVector,
    container: Color,
    content: Color,
    modifier: Modifier = Modifier,
    size: Dp = 48.dp,
    shapeId: IconShapeId = LocalIconShape.current,
) {
    Box(
        modifier
            .size(size)
            .clip(iconShape(shapeId))
            .background(container),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = content, modifier = Modifier.size(size * 0.5f))
    }
}

@Composable
fun StatusPill(status: Status, modifier: Modifier = Modifier) {
    val (content, container) = statusColors(status)
    Surface(modifier, shape = CircleShape, color = container, contentColor = content) {
        Row(
            Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(statusIcon(status), contentDescription = null, modifier = Modifier.size(14.dp))
            Text(statusLabel(status), style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        modifier = modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
    )
}

@Composable
fun PondTopBar(
    title: String,
    scrollBehavior: TopAppBarScrollBehavior,
    onBack: (() -> Unit)? = null,
    actions: @Composable () -> Unit = {},
) {
    val haptic = rememberHaptic()
    LargeTopAppBar(
        title = {
            val fraction = scrollBehavior.state.collapsedFraction
            val onSurface = MaterialTheme.colorScheme.onSurface
            val primary = MaterialTheme.colorScheme.primary
            Text(
                title,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = androidx.compose.ui.graphics.lerp(onSurface, primary, fraction),
                modifier = Modifier.graphicsLayer {
                    val scale = 1f - 0.08f * fraction
                    scaleX = scale
                    scaleY = scale
                    transformOrigin = androidx.compose.ui.graphics.TransformOrigin(0f, 0.5f)
                    translationY = -6.dp.toPx() * fraction
                },
            )
        },
        navigationIcon = {
            if (onBack != null) {
                FilledTonalIconButton(
                    colors = pondIconButtonColors(),
                    onClick = {
                        haptic.tap()
                        onBack()
                    },
                    modifier = Modifier.padding(start = 8.dp),
                ) {
                    Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = null)
                }
            }
        },
        actions = {
            Row(Modifier.padding(end = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                actions()
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface,
            scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
            navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            actionIconContentColor = MaterialTheme.colorScheme.onSurface,
        ),
        scrollBehavior = scrollBehavior,
    )
}

@Composable
fun pondIconButtonColors(): IconButtonColors = IconButtonDefaults.filledTonalIconButtonColors(
    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
    contentColor = MaterialTheme.colorScheme.onSurface,
    disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = 0.5f),
    disabledContentColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
)

@Composable
fun pondSwitchColors(): SwitchColors {
    val c = MaterialTheme.colorScheme
    return SwitchDefaults.colors(
        checkedThumbColor = c.onPrimary,
        checkedTrackColor = c.primary,
        checkedBorderColor = c.primary,
        uncheckedThumbColor = c.outline,
        uncheckedTrackColor = c.surfaceContainerHighest,
        uncheckedBorderColor = c.outline,
    )
}

@Composable
fun SwitchRow(
    title: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    icon: ImageVector? = null,
    enabled: Boolean = true,
) {
    val haptic = rememberHaptic()
    Row(
        modifier
            .fillMaxWidth()
            .alpha(if (enabled) 1f else 0.5f)
            .clip(MaterialTheme.shapes.medium)
            .toggleable(
                value = checked,
                enabled = enabled,
                role = Role.Switch,
                onValueChange = {
                    haptic.toggle(it)
                    onChange(it)
                },
            )
            .padding(vertical = 8.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (subtitle != null) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Switch(checked = checked, onCheckedChange = null, enabled = enabled, colors = pondSwitchColors())
    }
}

@Composable
fun SliderRow(
    title: String,
    value: Float,
    range: ClosedFloatingPointRange<Float>,
    format: (Float) -> String,
    onCommit: (Float) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    var live by remember(value) { mutableFloatStateOf(value) }
    Column(modifier.fillMaxWidth().alpha(if (enabled) 1f else 0.5f).padding(vertical = 4.dp, horizontal = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(
                format(live),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Slider(
            value = live,
            onValueChange = { live = it },
            onValueChangeFinished = { onCommit(live) },
            valueRange = range,
            enabled = enabled,
            colors = SliderDefaults.colors(
                thumbColor = MaterialTheme.colorScheme.primary,
                activeTrackColor = MaterialTheme.colorScheme.primary,
                inactiveTrackColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            ),
        )
    }
}

@Composable
fun <T> Segmented(
    options: List<Pair<T, String>>,
    selected: T,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val haptic = rememberHaptic()
    SingleChoiceSegmentedButtonRow(modifier.fillMaxWidth()) {
        options.forEachIndexed { index, option ->
            SegmentedButton(
                selected = option.first == selected,
                onClick = {
                    haptic.tap()
                    onSelect(option.first)
                },
                shape = SegmentedButtonDefaults.itemShape(index, options.size),
                enabled = enabled,
                colors = SegmentedButtonDefaults.colors(
                    activeContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    activeContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    activeBorderColor = MaterialTheme.colorScheme.primary,
                    inactiveContainerColor = Color.Transparent,
                    inactiveContentColor = MaterialTheme.colorScheme.onSurface,
                    inactiveBorderColor = MaterialTheme.colorScheme.outlineVariant,
                ),
                label = { Text(option.second, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            )
        }
    }
}

@Composable
fun <T> ChoiceFlow(
    options: List<Pair<T, String>>,
    selected: T,
    onSelect: (T) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val haptic = rememberHaptic()
    FlowRow(
        modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        options.forEach { option ->
            val isSelected = option.first == selected
            FilterChip(
                selected = isSelected,
                onClick = {
                    haptic.tap()
                    onSelect(option.first)
                },
                enabled = enabled,
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                    selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    selectedLeadingIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                label = { Text(option.second) },
                leadingIcon = if (isSelected) {
                    { Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(18.dp)) }
                } else {
                    null
                },
            )
        }
    }
}

@Composable
fun EvidenceRow(item: Evidence, modifier: Modifier = Modifier) {
    val persian = LocalPersian.current
    val context = LocalContext.current
    val haptic = rememberHaptic()
    val colors = MaterialTheme.colorScheme
    val tint = when (item.level) {
        Status.INFO, Status.PENDING -> colors.outline
        else -> statusColors(item.level).first
    }
    val label = item.label.get(persian)
    val value = displayValue(item.value, persian)
    val detail = item.detail?.get(persian)
    Row(
        modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.small)
            .combinedClickable(
                onClick = {},
                onLongClick = {
                    haptic.confirm()
                    copyToClipboard(context, "$label: $value", value)
                },
            )
            .padding(vertical = 8.dp, horizontal = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
            statusIcon(item.level),
            contentDescription = null,
            tint = tint,
            modifier = Modifier.padding(top = 2.dp).size(18.dp),
        )
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium.copy(textDirection = TextDirection.Content),
                color = colors.onSurfaceVariant,
            )
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium.copy(
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    textDirection = TextDirection.Content,
                ),
                color = colors.onSurface,
            )
            if (!detail.isNullOrBlank()) {
                Text(
                    detail,
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = if (persian) FontFamily.Default else FontFamily.Monospace,
                        textDirection = TextDirection.Content,
                    ),
                    color = colors.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
fun PaddingValues.withExtra(
    horizontal: Dp = 0.dp,
    top: Dp = 0.dp,
    bottom: Dp = 0.dp,
): PaddingValues {
    val direction = androidx.compose.ui.platform.LocalLayoutDirection.current
    return PaddingValues(
        start = calculateStartPadding(direction) + horizontal,
        top = calculateTopPadding() + top,
        end = calculateEndPadding(direction) + horizontal,
        bottom = calculateBottomPadding() + bottom,
    )
}

@Composable
fun tabInsets(): androidx.compose.foundation.layout.WindowInsets =
    androidx.compose.foundation.layout.WindowInsets.safeDrawing.only(
        androidx.compose.foundation.layout.WindowInsetsSides.Top +
            androidx.compose.foundation.layout.WindowInsetsSides.Horizontal,
    )
