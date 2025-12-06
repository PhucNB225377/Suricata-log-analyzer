#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class SharedQueue {
    private:
        std::queue<T> q;
        std::mutex mtx;
        std::condition_variable cv;

    public:
        SharedQueue() {}

        void push(T val) {
            std::lock_guard<std::mutex> lock(mtx);
            {q.push(val);}
            cv.notify_one();
            return;
        }

        T front() {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [this]{ return !q.empty(); });
            T val = q.front();
            q.pop();
            lock.unlock();
            return val;
        }

        bool empty() {
            std::lock_guard<std::mutex> lock(mtx);
            return q.empty();
        }
};