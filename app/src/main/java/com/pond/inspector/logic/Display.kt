package com.pond.inspector.logic

fun displayValue(value: String, persian: Boolean): String {
    if (!persian) return value
    return when (value.trim()) {
        "present" -> "موجود"
        "not visible" -> "دیده نشد"
        "not found" -> "پیدا نشد"
        "none" -> "هیچ"
        "off" -> "خاموش"
        "on" -> "روشن"
        "unreadable" -> "خوانده نشد"
        "available" -> "در دسترس"
        "not available" -> "در دسترس نیست"
        "local properties only" -> "فقط ویژگی‌های محلی"
        "true" -> "بله"
        "false" -> "خیر"
        "absent" -> "نیست"
        "software" -> "نرم‌افزار"
        "hardware" -> "سخت‌افزار"
        "trusted environment" -> "محیط مطمئن"
        "strongbox" -> "StrongBox"
        "unknown" -> "نامشخص"
        "—" -> "—"
        else -> value
    }
}
