## 2024-10-12 - Hidden O(N^2) I/O in Parallel Workers
**Learning:** When processing items in parallel (e.g., files in a directory), ensure shared resources (like a config file or database) are not read/written for *every* item individually. In `dataGhost`, each worker read the directory's `.ghost` file, leading to O(N^2) I/O operations (Read file N times * Size of file (proportional to N)).
**Action:** Implement a shared, thread-safe memory cache for the resource. Load it once (lazily), and let workers access the in-memory copy. Use proper locking (`sync.RWMutex`) to allow concurrent reads.

## 2024-10-12 - Defer Unlock in Complex Control Flows
**Learning:** Using `defer mutex.Unlock()` is convenient but dangerous in functions with complex control flows that require manual unlocking (e.g., waiting for user input without holding the lock). Mixing `defer` and manual unlocking often leads to "unlock of unlocked mutex" panics.
**Action:** In complex functions where locks must be released and re-acquired, avoid `defer unlock()`. Handle locking and unlocking manually and explicitly at every return point.
