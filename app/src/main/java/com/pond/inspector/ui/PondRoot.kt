package com.pond.inspector.ui

import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pond.inspector.PondViewModel
import com.pond.inspector.model.AppLanguage
import com.pond.inspector.model.DensityStyle
import com.pond.inspector.model.MotionStyle
import com.pond.inspector.ui.nav.PondApp
import com.pond.inspector.ui.nav.Routes
import com.pond.inspector.ui.theme.PondTheme

@Composable
fun PondRoot(vm: PondViewModel = viewModel()) {
    val appearance by vm.appearance.collectAsStateWithLifecycle()
    val scanPrefs by vm.scan.collectAsStateWithLifecycle()
    val a = appearance
    val s = scanPrefs
    if (a == null || s == null) {
        Box(Modifier.fillMaxSize())
        return
    }

    LaunchedEffect(a.language) {
        val wanted = when (a.language) {
            AppLanguage.System -> LocaleListCompat.getEmptyLocaleList()
            AppLanguage.English -> LocaleListCompat.forLanguageTags("en")
            AppLanguage.Persian -> LocaleListCompat.forLanguageTags("fa")
        }
        if (AppCompatDelegate.getApplicationLocales().toLanguageTags() != wanted.toLanguageTags()) {
            AppCompatDelegate.setApplicationLocales(wanted)
        }
    }

    val systemPersian = LocalConfiguration.current.locales.get(0)?.language == "fa"
    val persian = when (a.language) {
        AppLanguage.System -> systemPersian
        AppLanguage.English -> false
        AppLanguage.Persian -> true
    }
    val start = remember { if (s.onboardingDone) Routes.HOME else Routes.ONBOARDING }

    PondTheme(a) {
        CompositionLocalProvider(
            LocalPersian provides persian,
            LocalLayoutDirection provides if (persian) LayoutDirection.Rtl else LayoutDirection.Ltr,
            LocalPad provides if (a.density == DensityStyle.Compact) 12.dp else 16.dp,
            LocalIconShape provides a.iconShape,
            LocalShowRaw provides a.showRaw,
            LocalReduced provides (a.motion == MotionStyle.Reduced),
        ) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                PondApp(vm, start)
            }
        }
    }
}
