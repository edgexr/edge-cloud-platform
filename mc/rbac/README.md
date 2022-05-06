# RBAC

This RBAC package is based on Casbin. Unfortunately Casbin could not meet our needs because of the way it is architected. The master controller needs to be horizontally scalable, which Casbin could not support safely.

## Casbin Architecture

Casbin treats the in-memory cache of policies and groups as the source of truth. It writes to in-memory first, then writes to the "adapter", which is an interface to persistent storage.

This is fine for a single process, but does not work well for multiple processes. For multiple processes sharing the same persistent storage, a "watcher" needs to be implemented to notify the processes of any changes to the storage. Besides the fact that there is no watcher implemented for postgres, the main problem here is that the persistent storage is not treated as the source of truth. If access to the persistent storage is lost, each process will build up its own separate view of accumulated changes in the cache that will be inconsistent with other processes. Additionally the watcher makes no guarantees about notifications, only guaranteeing slow eventual consistency by reloading the entire cache from persistent storage periodically.

## Rearchitect Casbin

Casbin should treat the persistent storage as the source of truth, rather than the in-memory cache. Much like the edge-cloud controller treats etcd as the source of truth and updates its cache only from etcd watcher callbacks, we attempted to implement the same model in a Casbin drop-in replacement, leveraging the Casbin libraries. In this model, RBAC writes to persistent storage first. The cache is only updated on watcher notifications of changes to the persistent storage. We continue to use the Model struct from Casbin to store policies in memory as the cache, so that reads do not require accessing postgres.

Note that the cache is only updated via the watcher notify thread. It cannot be updated from both an API thread making the change and the watcher, because it would lead to race conditions and inconsistent cache state.

Unfortunately, postgres does not easily support a watcher that can be synchronized like etcd. While it supports a listener/notify framework, it does not allow easy access to transaction ids. This leads to a problem with commands run in series where subsequent commands rely on changes done by previous commands (like a test script). A command must wait until the process gets that notification of the change it made and the cache is updated before it can return and allow the script to run the next command. Because of this many tests end up failing. So this attempt was abandoned.

## Non-cached RBAC (current implementation)

Most of the postgres work on horizontal scaling has been to support postgres scaling, rather than to support caching and scaling of the processes that access postgres. Without support for that, we must dispense of the local cache and have all reads go direct to postgres. Trying to leverage the existing Casbin libraries and gorm-adapter to do so would have resulted in very inefficient accesses to postgres (three accesses for each enforce call to read related policies, groups, and admin policies), plus rebuilding and repopulating the Casbin Model struct each time.

Rather than deal with that overhead, we implement our own RBAC that is hard-coded to use postgres, and leverages postgres SQL joins to do the work of figuring out the allowed users, rather than the Casbin Model struct. The drawbacks are that we are tied to postgres as the persistent storage, and the model is hard-coded in the code, rather than represented by a model config string. The primary disadvantage is there is no cache, so all enforce calls must access postgres (of which there can be one per item in show commands). The advantage is a simple RBAC that does not have the complexity of caching and leverages postgres to do some of the work. The functions and code organization of this RBAC package are meant to mimic Casbin as closely as possible for easy understanding of those familiar with the Casbin code, and to make it easy to drop-in replace this RBAC package for Casbin (or vice-versa).

This also keeps the data stored in postgres in the same format, so that it is backwards and forward compatible with Casbin (technically gorm-adapter).

## Possible Future Alternative: Rearchitected Casbin with Etcd

An alternative that would give the advantage of caching with the safety of cache consistency would be to use a rearchitected Casbin with etcd as the persistent storage. From the edge-cloud controller, we know how to synchronize a local cache via an etcd watcher, using transaction ids to stall commands until the cache is updated. The drawback of this approach would be that we'd have both a postgres database and an etcd database at the global level, which is more complex and requires more maintainenance. But if we find that an RBAC cache is necessary for performance, this would probably be the best option to explore. Given how much postgres is optimized for heavy production use, it seems unlikely that this is needed.
