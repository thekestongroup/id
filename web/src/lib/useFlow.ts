import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError, type Flow } from './api'
import { follow } from './session'

/**
 * For the sign-in pages: the app that's asking (from ?authRequestID), and
 * the server's view of where this page fits. If the server says another
 * page should be showing (e.g. already signed in), it goes there.
 */
export function useFlow(page: Flow['step']) {
  const route = useRoute()
  const router = useRouter()
  const authRequestID = computed(() => (route.query.authRequestID as string | undefined) || undefined)
  const flow = ref<Flow>()
  const error = ref<string>()
  const loading = ref(true)

  onMounted(async () => {
    try {
      const f = await api.flow(authRequestID.value)
      flow.value = f
      if (f.step !== page) {
        await follow(router, f, authRequestID.value)
      }
    } catch (e) {
      error.value = e instanceof ApiError ? e.message : 'Something went wrong. Try again.'
    } finally {
      loading.value = false
    }
  })

  /** After a step succeeds: on to the next one. */
  const next = (f: Flow) => follow(router, f, authRequestID.value)

  return { authRequestID, flow, client: computed(() => flow.value?.client), error, loading, next }
}
