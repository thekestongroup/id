import {
  BookOpen,
  GraduationCap,
  KeyRound,
  Mail,
  MapPin,
  RefreshCw,
  User,
  Users,
} from '@lucide/vue'
import type { Component } from 'vue'

/** The icons the server names for each scope (see internal/api/scopes.go). */
const icons: Record<string, Component> = {
  user: User,
  mail: Mail,
  'refresh-cw': RefreshCw,
  'book-open': BookOpen,
  users: Users,
  'graduation-cap': GraduationCap,
  'map-pin': MapPin,
  'key-round': KeyRound,
}

export const scopeIcon = (name: string): Component => icons[name] ?? KeyRound
