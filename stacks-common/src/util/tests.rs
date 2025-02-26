// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::{Arc, Mutex};
/// `TestFlag` is a thread-safe utility designed for managing shared state in testing scenarios. It wraps
/// a value of type `T` inside an `Arc<Mutex<Option<T>>>`, allowing you to set and retrieve a value
/// across different parts of your codebase while ensuring thread safety.
///
/// This structure is particularly useful when:
/// - You need a global or static variable in tests.
/// - You want to control the execution of custom test code paths by setting and checking a shared value.
///
/// # Type Parameter
/// - `T`: The type of the value managed by the `TestFlag`. It must implement the `Default` and `Clone` traits.
///
/// # Examples
///
/// ```rust
/// use stacks_common::util::tests::TestFlag;
/// use std::sync::{Arc, Mutex};
///
/// // Create a TestFlag instance
/// let test_flag = TestFlag::default();
///
/// // Set a value in the test flag
/// test_flag.set("test_value".to_string());
///
/// // Retrieve the value
/// assert_eq!(test_flag.get(), "test_value".to_string());
///
/// // Reset the value to default
/// test_flag.set("".to_string());
/// assert_eq!(test_flag.get(), "".to_string());
/// ```
#[derive(Clone)]
pub struct TestFlag<T>(pub Arc<Mutex<Option<T>>>);

impl<T: Default + Clone> Default for TestFlag<T> {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }
}

impl<T> TestFlag<T> {
    pub fn new(initial_value: T) -> Self {
        Self(Arc::new(Mutex::new(Some(initial_value))))
    }
}

impl<T: Default + Clone> TestFlag<T> {
    /// Sets the value of the test flag.
    ///
    /// This method updates the value stored inside the `TestFlag`, replacing any existing value.
    ///
    /// # Arguments
    /// - `value`: The new value to set for the `TestFlag`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let test_flag = TestFlag::default();
    /// test_flag.set(42);
    /// assert_eq!(test_flag.get(), 42);
    /// ```
    pub fn set(&self, value: T) {
        *self.0.lock().unwrap() = Some(value);
    }

    /// Retrieves the current value of the test flag.
    ///
    /// If no value has been set, this method returns the default value for the type `T`.
    ///
    /// # Returns
    /// - The current value of the test flag, or the default value of `T` if none has been set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let test_flag = TestFlag::default();
    ///
    /// // Get the default value
    /// assert_eq!(test_flag.get(), 0); // For T = i32, default is 0
    ///
    /// // Set a value
    /// test_flag.set(123);
    ///
    /// // Get the updated value
    /// assert_eq!(test_flag.get(), 123);
    /// ```
    pub fn get(&self) -> T {
        self.0.lock().unwrap().clone().unwrap_or_default()
    }
}
