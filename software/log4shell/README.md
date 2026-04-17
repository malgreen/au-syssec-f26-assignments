# Log4Shell Exploit Example

## 0. Setup

1. Install `docker` and `docker-compose`
1. If not done already, initialize submodules with:

    ```sh
    git submodule update --init --recursive
    ```

## 1. Exploit

1. Go into the `log4shell-dockerized` directory with:

    ```sh
    cd log4shell-dockerized
    ```

1. Bring up the Docker Compose stack with:

    ```sh
    docker compose up --build
    ```

    this will execute the exploit

1. Open another shell and check that the exploit worked with:

    ```sh
    docker exec log4shell-vuln ls /tmp
    ```
    this should show a file called `pwned.txt``

    ```sh
    docker exec log4shell-vuln cat /tmp/pwned.txt
    ```
    this should print "*WISEFLOW WAS HERE B-)*"
