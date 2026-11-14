package com.pond.inspector.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.pond.inspector.ui.LocalPad
import com.pond.inspector.ui.LocalReduced
import kotlinx.coroutines.delay
import androidx.compose.runtime.withFrameNanos

@Composable
fun DeferredScreen(delayMs: Long = 230L, content: @Composable () -> Unit) {
    val reduced = LocalReduced.current
    var ready by rememberSaveable { mutableStateOf(reduced) }
    LaunchedEffect(Unit) {
        if (!ready) {
            if (delayMs > 0) delay(delayMs)
            withFrameNanos { }
            ready = true
        }
    }
    AnimatedContent(
        targetState = ready,
        modifier = Modifier.fillMaxSize(),
        transitionSpec = {
            if (reduced) {
                fadeIn(tween(0)) togetherWith fadeOut(tween(0))
            } else {
                (fadeIn(tween(280)) + slideInVertically(tween(340)) { it / 28 }) togetherWith fadeOut(tween(100))
            }
        },
        label = "deferred",
    ) { loaded ->
        if (loaded) content() else Skeleton()
    }
}

@Composable
private fun Skeleton() {
    val pad = LocalPad.current
    val pulse by rememberInfiniteTransition(label = "skeleton").animateFloat(
        initialValue = 0.35f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(tween(750), RepeatMode.Reverse),
        label = "pulse",
    )
    val color = MaterialTheme.colorScheme.surfaceContainerHigh
    Column(
        Modifier
            .fillMaxSize()
            .padding(WindowInsets.safeDrawing.asPaddingValues())
            .padding(horizontal = pad, vertical = 12.dp)
            .alpha(pulse),
    ) {
        Spacer(Modifier.height(72.dp))
        Bar(color, 40.dp, 0.55f)
        Spacer(Modifier.height(24.dp))
        repeat(4) {
            Bar(color, 96.dp, 1f)
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun Bar(color: androidx.compose.ui.graphics.Color, h: androidx.compose.ui.unit.Dp, fraction: Float) {
    Spacer(
        Modifier
            .fillMaxWidth(fraction)
            .height(h)
            .clip(RoundedCornerShape(20.dp))
            .background(color),
    )
}
