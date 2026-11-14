package com.pond.inspector.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.pond.inspector.model.AppLanguage
import com.pond.inspector.model.AppearancePrefs
import com.pond.inspector.model.DensityStyle
import com.pond.inspector.model.DetectorIds
import com.pond.inspector.model.IconShapeId
import com.pond.inspector.model.MotionStyle
import com.pond.inspector.model.PaletteStyle
import com.pond.inspector.model.ScanPrefs
import com.pond.inspector.model.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.pondStore by preferencesDataStore(name = "pond")

class PondStore(private val context: Context) {
    val appearance: Flow<AppearancePrefs> = context.pondStore.data
        .map { it.toAppearance() }
        .catch { emit(AppearancePrefs()) }

    val scan: Flow<ScanPrefs> = context.pondStore.data
        .map { it.toScan() }
        .catch { emit(ScanPrefs()) }

    suspend fun updateAppearance(block: (AppearancePrefs) -> AppearancePrefs) {
        context.pondStore.edit { prefs ->
            prefs.write(block(prefs.toAppearance()))
        }
    }

    suspend fun updateScan(block: (ScanPrefs) -> ScanPrefs) {
        context.pondStore.edit { prefs ->
            prefs.write(block(prefs.toScan()))
        }
    }

    private fun Preferences.toAppearance() = AppearancePrefs(
        themeMode = this[Keys.theme].enumOr(ThemeMode.System),
        wallpaperColors = this[Keys.wallpaper] ?: true,
        seed = this[Keys.seed] ?: AppearancePrefs().seed,
        palette = this[Keys.palette].enumOr(PaletteStyle.TonalSpot),
        contrast = this[Keys.contrast] ?: 0f,
        pureBlack = this[Keys.pureBlack] ?: false,
        cornerScale = this[Keys.corners] ?: 1f,
        textScale = this[Keys.text] ?: 1f,
        motion = this[Keys.motion].enumOr(MotionStyle.Expressive),
        haptics = this[Keys.haptics] ?: true,
        iconShape = this[Keys.icon].enumOr(IconShapeId.Cookie4),
        density = this[Keys.density].enumOr(DensityStyle.Comfortable),
        language = this[Keys.language].enumOr(AppLanguage.System),
        showRaw = this[Keys.raw] ?: false,
    )

    private fun Preferences.toScan() = ScanPrefs(
        autoScan = this[Keys.auto] ?: true,
        notifications = this[Keys.notifications] ?: false,
        liveUpdate = this[Keys.live] ?: true,
        onlineCrl = this[Keys.online] ?: false,
        onboardingDone = this[Keys.onboarding] ?: false,
        enabled = if (contains(Keys.enabled)) {
            val known = this[Keys.known] ?: DetectorIds.legacy
            this[Keys.enabled].orEmpty() + (DetectorIds.all - known)
        } else {
            DetectorIds.all
        },
    )

    private fun androidx.datastore.preferences.core.MutablePreferences.write(value: AppearancePrefs) {
        this[Keys.theme] = value.themeMode.name
        this[Keys.wallpaper] = value.wallpaperColors
        this[Keys.seed] = value.seed
        this[Keys.palette] = value.palette.name
        this[Keys.contrast] = value.contrast
        this[Keys.pureBlack] = value.pureBlack
        this[Keys.corners] = value.cornerScale
        this[Keys.text] = value.textScale
        this[Keys.motion] = value.motion.name
        this[Keys.haptics] = value.haptics
        this[Keys.icon] = value.iconShape.name
        this[Keys.density] = value.density.name
        this[Keys.language] = value.language.name
        this[Keys.raw] = value.showRaw
    }

    private fun androidx.datastore.preferences.core.MutablePreferences.write(value: ScanPrefs) {
        this[Keys.auto] = value.autoScan
        this[Keys.notifications] = value.notifications
        this[Keys.live] = value.liveUpdate
        this[Keys.online] = value.onlineCrl
        this[Keys.onboarding] = value.onboardingDone
        this[Keys.enabled] = value.enabled
        this[Keys.known] = DetectorIds.all
    }

    private inline fun <reified T : Enum<T>> String?.enumOr(default: T): T =
        enumValues<T>().firstOrNull { it.name == this } ?: default

    private object Keys {
        val theme = stringPreferencesKey("theme")
        val wallpaper = booleanPreferencesKey("wallpaper")
        val seed = intPreferencesKey("seed")
        val palette = stringPreferencesKey("palette")
        val contrast = floatPreferencesKey("contrast")
        val pureBlack = booleanPreferencesKey("pure_black")
        val corners = floatPreferencesKey("corners")
        val text = floatPreferencesKey("text")
        val motion = stringPreferencesKey("motion")
        val haptics = booleanPreferencesKey("haptics")
        val icon = stringPreferencesKey("icon")
        val density = stringPreferencesKey("density")
        val language = stringPreferencesKey("language")
        val raw = booleanPreferencesKey("raw")
        val auto = booleanPreferencesKey("auto")
        val notifications = booleanPreferencesKey("notifications")
        val live = booleanPreferencesKey("live")
        val online = booleanPreferencesKey("online")
        val onboarding = booleanPreferencesKey("onboarding")
        val enabled = stringSetPreferencesKey("enabled")
        val known = stringSetPreferencesKey("known_detectors")
    }
}
