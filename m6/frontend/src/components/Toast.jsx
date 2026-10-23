import { createContext, useCallback, useContext, useRef, useState } from 'react'

const ToastContext = createContext(() => {})
export const useToast = () => useContext(ToastContext)

export function ToastProvider({ children }) {
  const [msg, setMsg] = useState('')
  const [on, setOn] = useState(false)
  const timer = useRef()
  const show = useCallback((m) => {
    clearTimeout(timer.current)
    setMsg(m); setOn(true)
    timer.current = setTimeout(() => setOn(false), 2600)
  }, [])
  return (
    <ToastContext.Provider value={show}>
      {children}
      <div id="toast" className={on ? 'on' : undefined} role="status">{msg}</div>
    </ToastContext.Provider>
  )
}
