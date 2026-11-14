package com.pond.inspector.ui.nav

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.background
import androidx.compose.ui.zIndex
import com.pond.inspector.ui.LocalBarInset
import com.pond.inspector.ui.LocalPersian
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.pond.inspector.PondViewModel
import com.pond.inspector.ui.LocalReduced
import com.pond.inspector.ui.components.DeferredScreen
import com.pond.inspector.ui.components.rememberHaptic
import com.pond.inspector.ui.screens.AboutScreen
import com.pond.inspector.ui.screens.AppearanceScreen
import com.pond.inspector.ui.screens.DetectorScreen
import com.pond.inspector.ui.screens.DeviceScreen
import com.pond.inspector.ui.screens.HomeScreen
import com.pond.inspector.ui.screens.OnboardingScreen
import com.pond.inspector.ui.screens.ScanSettingsScreen
import com.pond.inspector.ui.screens.SettingsScreen
import com.pond.inspector.ui.tr

object Routes {
    const val ONBOARDING = "onboarding"
    const val HOME = "home"
    const val DEVICE = "device"
    const val SETTINGS = "settings"
    const val APPEARANCE = "settings/appearance"
    const val SCAN = "settings/scan"
    const val ABOUT = "settings/about"
    const val DETECTOR = "detector/{id}"

    fun detector(id: String) = "detector/$id"
}

private data class Tab(val route: String, val title: String, val icon: ImageVector)

private val BarHeight = 68.dp
private val BarMargin = 14.dp
private val tabRoutes = listOf(Routes.HOME, Routes.DEVICE, Routes.SETTINGS)

@Composable
fun PondApp(vm: PondViewModel, start: String) {
    val nav = rememberNavController()
    val entry by nav.currentBackStackEntryAsState()
    val route = entry?.destination?.route
    val reduced = LocalReduced.current
    val persian = LocalPersian.current
    val haptic = rememberHaptic()
    val tabs = listOf(
        Tab(Routes.HOME, tr("Scan", "اسکن"), Icons.Rounded.Shield),
        Tab(Routes.DEVICE, tr("Device", "دستگاه"), Icons.Rounded.PhoneAndroid),
        Tab(Routes.SETTINGS, tr("Settings", "تنظیمات"), Icons.Rounded.Settings),
    )
    val showBar = route != null && route in tabRoutes
    val navBottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()
    val barInset = navBottom + BarMargin + BarHeight

    fun idx(r: String?) = tabRoutes.indexOf(r)

    val slideMs = 280
    val ease = FastOutSlowInEasing
    val isTabMove: AnimatedContentTransitionScope<androidx.navigation.NavBackStackEntry>.() -> Boolean = {
        idx(initialState.destination.route) >= 0 && idx(targetState.destination.route) >= 0
    }

    CompositionLocalProvider(LocalBarInset provides barInset) {
        Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface)) {
            NavHost(
                navController = nav,
                startDestination = start,
                modifier = Modifier.fillMaxSize(),
                enterTransition = {
                    if (reduced) {
                        EnterTransition.None
                    } else if (isTabMove()) {
                        val forward = idx(targetState.destination.route) > idx(initialState.destination.route)
                        val left = forward != persian
                        slideInHorizontally(tween(slideMs, easing = ease)) { if (left) it / 3 else -it / 3 } +
                            fadeIn(tween(slideMs, easing = ease))
                    } else {
                        slideInHorizontally(tween(slideMs, easing = ease)) { if (persian) -it / 4 else it / 4 } +
                            fadeIn(tween(slideMs, easing = ease))
                    }
                },
                exitTransition = {
                    if (reduced) {
                        ExitTransition.None
                    } else if (isTabMove()) {
                        val forward = idx(targetState.destination.route) > idx(initialState.destination.route)
                        val left = forward != persian
                        slideOutHorizontally(tween(slideMs, easing = ease)) { if (left) -it / 3 else it / 3 } +
                            fadeOut(tween(slideMs / 2, easing = ease))
                    } else {
                        slideOutHorizontally(tween(slideMs, easing = ease)) { if (persian) it / 6 else -it / 6 } +
                            fadeOut(tween(slideMs / 2, easing = ease))
                    }
                },
                popEnterTransition = {
                    if (reduced) {
                        EnterTransition.None
                    } else if (isTabMove()) {
                        val forward = idx(targetState.destination.route) > idx(initialState.destination.route)
                        val left = forward != persian
                        slideInHorizontally(tween(slideMs, easing = ease)) { if (left) it / 3 else -it / 3 } +
                            fadeIn(tween(slideMs, easing = ease))
                    } else {
                        slideInHorizontally(tween(slideMs, easing = ease)) { if (persian) it / 6 else -it / 6 } +
                            fadeIn(tween(slideMs, easing = ease))
                    }
                },
                popExitTransition = {
                    if (reduced) {
                        ExitTransition.None
                    } else if (isTabMove()) {
                        val forward = idx(targetState.destination.route) > idx(initialState.destination.route)
                        val left = forward != persian
                        slideOutHorizontally(tween(slideMs, easing = ease)) { if (left) -it / 3 else it / 3 } +
                            fadeOut(tween(slideMs / 2, easing = ease))
                    } else {
                        slideOutHorizontally(tween(slideMs, easing = ease)) { if (persian) -it / 4 else it / 4 } +
                            fadeOut(tween(slideMs / 2, easing = ease))
                    }
                },
            ) {
                composable(Routes.ONBOARDING) {
                    DeferredScreen(60L) {
                        OnboardingScreen(vm) {
                            nav.navigate(Routes.HOME) {
                                popUpTo(Routes.ONBOARDING) { inclusive = true }
                                launchSingleTop = true
                            }
                        }
                    }
                }
                composable(Routes.HOME) {
                    DeferredScreen(80L) { HomeScreen(vm, onOpen = { nav.navigate(Routes.detector(it)) }) }
                }
                composable(Routes.DEVICE) {
                    DeferredScreen { DeviceScreen(vm) }
                }
                composable(Routes.SETTINGS) {
                    DeferredScreen(150L) {
                        SettingsScreen(
                            onAppearance = { nav.navigate(Routes.APPEARANCE) },
                            onScan = { nav.navigate(Routes.SCAN) },
                            onAbout = { nav.navigate(Routes.ABOUT) },
                        )
                    }
                }
                composable(Routes.APPEARANCE) {
                    DeferredScreen { AppearanceScreen(vm, onBack = { nav.popBackStack() }) }
                }
                composable(Routes.SCAN) {
                    DeferredScreen { ScanSettingsScreen(vm, onBack = { nav.popBackStack() }) }
                }
                composable(Routes.ABOUT) {
                    DeferredScreen { AboutScreen(onBack = { nav.popBackStack() }) }
                }
                composable(
                    Routes.DETECTOR,
                    arguments = listOf(navArgument("id") { type = NavType.StringType }),
                ) { backStack ->
                    DeferredScreen {
                        DetectorScreen(
                            vm = vm,
                            id = backStack.arguments?.getString("id").orEmpty(),
                            onBack = { nav.popBackStack() },
                        )
                    }
                }
            }

            AnimatedVisibility(
                visible = showBar,
                modifier = Modifier.align(Alignment.BottomCenter).zIndex(2f),
                enter = if (reduced) EnterTransition.None else slideInVertically(tween(300, easing = ease)) { it } + fadeIn(tween(200)),
                exit = if (reduced) ExitTransition.None else slideOutVertically(tween(240, easing = ease)) { it } + fadeOut(tween(160)),
            ) {
                CapsuleBar(
                    tabs = tabs,
                    selected = idx(route).coerceAtLeast(0),
                    reduced = reduced,
                    modifier = Modifier.padding(bottom = navBottom + BarMargin, start = 28.dp, end = 28.dp),
                    onSelect = { i ->
                        val target = tabs[i].route
                        if (route != target) {
                            haptic.tap()
                            nav.navigate(target) {
                                popUpTo(Routes.HOME) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun CapsuleBar(
    tabs: List<Tab>,
    selected: Int,
    reduced: Boolean,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    val position = remember { Animatable(selected.toFloat()) }
    LaunchedEffect(selected, reduced) {
        if (reduced) {
            position.snapTo(selected.toFloat())
        } else {
            position.animateTo(
                selected.toFloat(),
                spring(dampingRatio = 0.62f, stiffness = Spring.StiffnessMediumLow),
            )
        }
    }
    val colors = MaterialTheme.colorScheme
    Surface(
        modifier = modifier.widthIn(max = 420.dp).fillMaxWidth().height(BarHeight),
        shape = CircleShape,
        color = colors.surfaceContainerHigh,
        tonalElevation = 0.dp,
        shadowElevation = 10.dp,
        border = BorderStroke(1.dp, colors.outlineVariant.copy(alpha = 0.55f)),
    ) {
        BoxWithConstraints(Modifier.fillMaxSize().padding(6.dp)) {
            val itemWidth = maxWidth / tabs.size
            val itemWidthPx = with(LocalDensity.current) { itemWidth.toPx() }
            Box(
                Modifier
                    .width(itemWidth)
                    .fillMaxHeight()
                    .graphicsLayer {
                        val dir = if (rtl) -1f else 1f
                        translationX = dir * position.value * itemWidthPx
                        val travel = kotlin.math.abs(position.value - selected)
                        scaleX = 1f + (travel * 0.12f).coerceAtMost(0.18f)
                    }
                    .clip(CircleShape)
                    .background(colors.primaryContainer),
            )
            Row(Modifier.fillMaxSize()) {
                tabs.forEachIndexed { i, tab ->
                    CapsuleItem(
                        tab = tab,
                        active = i == selected,
                        reduced = reduced,
                        onClick = { onSelect(i) },
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun CapsuleItem(
    tab: Tab,
    active: Boolean,
    reduced: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scale by animateFloatAsState(
        targetValue = if (active && !reduced) 1.14f else 1f,
        animationSpec = spring(dampingRatio = 0.45f, stiffness = Spring.StiffnessMedium),
        label = "tabScale",
    )
    val colors = MaterialTheme.colorScheme
    val tint = if (active) colors.onPrimaryContainer else colors.onSurfaceVariant
    Column(
        modifier
            .fillMaxHeight()
            .clip(CircleShape)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                role = Role.Tab,
                onClick = onClick,
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            tab.icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(24.dp).graphicsLayer {
                scaleX = scale
                scaleY = scale
            },
        )
        Text(
            tab.title,
            style = MaterialTheme.typography.labelMedium,
            color = tint,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
