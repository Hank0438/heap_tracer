# Heap-tracer (still working on it)
This is a project fork from Heaphopper, and try some innovative idea

## feature
feedback of memory dump improve testcase mutate form exist exploit model

## usage
* setup
```
mkvirtualenv -ppython3 heaphopper && pip install -e .
```

* trace
    * ptmalloc
    ```
    python3 start.py trace -a how2heap -e tcache_poisoning
    ```
    * jemalloc
    ```
    python3 start.py trace -a jemalloc -e arbitary_free
    ```

* poc
    

* gen
    * origin
    * feedback
