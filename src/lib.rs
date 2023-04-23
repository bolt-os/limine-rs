/*
 * Copyright (c) 2022 xvanc and contributors
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//! Limine Boot Protocol
//!
//! This modules implements the kernel-facing interface provided by the [Limine Boot Protocol],
//! a modern, minimal boot protocol for 64-bit higher-half kernels.
//!
//! # Features
//!
//! The protocol is built on a mechanism of requests and responses, collectively called
//! "features". The kernel requests various features from the bootloader by declaring
//! requests in the kernel binary. Each request contains a 256-bit identifier used to
//! locate it within the kernel binary, along with a revision number and an empty response
//! pointer field which is filled by the bootloader if the requested feature is supported.
//!
//! ```
//! static BOOTLOADER_INFO_REQUEST: BootloaderInfoRequest = BootloaderInfoRequest::new();
//!
//! fn main() {
//!     if let Some(response) = BOOTLOADER_INFO_REQUEST.response() {
//!         println!("{} {}", response.name(), response.version());
//!     } else {
//!         println!("the bootloader info feature is not supported by the bootloader!");
//!     }
//! }
//! ```
//!
//! [Limine Boot Protocol]: https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md

#![no_std]
// #![warn(clippy::cargo, clippy::pedantic, clippy::undocumented_unsafe_blocks)]
#![allow(
    clippy::cast_lossless,
    clippy::enum_glob_use,
    clippy::inline_always,
    clippy::must_use_candidate,
    clippy::unreadable_literal
)]
#![deny(
    clippy::semicolon_if_nothing_returned,
    clippy::debug_assert_with_mut_call
)]

use core::{
    cell::UnsafeCell,
    ffi::c_char,
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while s.add(len).read() != 0 {
        len += 1;
    }
    len
}

/// Request Identifier
///
/// A 256-bit identifier used to locate and uniquely identify requests within the
/// kernel image. The first 128 bits are constant across all identifiers and are used
/// to locate requests, and the last 128 bits are unique to each request type.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RequestId([u64; 4]);

impl core::fmt::Debug for RequestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RequestId([{:#018x}, {:#018x}, {:#018x}, {:#018x}])",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl RequestId {
    pub const fn new(uniq: [u64; 2]) -> RequestId {
        Self([0xc7b1dd30df4c8b88, 0x0a82e883a194f07b, uniq[0], uniq[1]])
    }

    pub const fn for_type<T: Request>() -> RequestId {
        T::ID
    }
}

/// A pointer to a resource provided by the bootloader
#[repr(transparent)]
#[derive(Clone, Copy)]
struct LiminePtr<T>(NonNull<T>);

impl<T> LiminePtr<T> {
    /// Creates a new `LiminePtr`
    ///
    /// # Safety
    ///
    /// `ptr` must not be null
    #[cfg(feature = "bootloader")]
    unsafe fn new_unchecked(ptr: *mut T) -> LiminePtr<T> {
        Self(NonNull::new_unchecked(ptr))
    }

    /// Returns a shared reference to the value
    ///
    /// # Safety
    ///
    /// The same requirements as for [`NonNull::as_ref()`] apply.
    unsafe fn as_ref(&self) -> &T {
        self.0.as_ref()
    }

    /// Returns a unique reference to the value
    ///
    /// # Safety
    ///
    /// The same requirements as for [`NonNull::as_mut()`] apply.
    unsafe fn as_mut(&mut self) -> &mut T {
        self.0.as_mut()
    }
}

impl LiminePtr<c_char> {
    /// Try to convert a C-string into a `&str`
    ///
    /// # Errors
    ///
    /// Returns `Err` if the pointer does not point a valid UTF-8 string.
    fn as_str<'a>(&self) -> Result<&'a str, core::str::Utf8Error> {
        let ptr = self.0.as_ptr().cast::<u8>();
        let data = unsafe { core::slice::from_raw_parts(ptr, strlen(ptr)) };
        core::str::from_utf8(data)
    }
}

type ArrayPtr<T> = LiminePtr<LiminePtr<T>>;

impl<'a, T: 'a> ArrayPtr<T> {
    fn make_iterator(&'a self, len: usize) -> impl Iterator<Item = &'a T> {
        unsafe {
            core::slice::from_raw_parts(self.0.as_ptr(), len)
                .iter()
                .map(|ptr| ptr.as_ref())
        }
    }

    fn make_iterator_mut(&'a mut self, len: usize) -> impl Iterator<Item = &'a mut T> {
        unsafe {
            core::slice::from_raw_parts_mut(self.0.as_ptr(), len)
                .iter_mut()
                .map(|ptr| ptr.as_mut())
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Uuid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

#[repr(C)]
pub struct File {
    revision: usize,
    address: *mut u8,
    size: usize,
    path: LiminePtr<c_char>,
    cmdline: Option<LiminePtr<c_char>>,
    media_type: u32,
    unused: u32,
    pub tftp_ip: u32,
    pub tftp_port: u32,
    pub partition_index: u32,
    pub mbr_disk_id: u32,
    pub gpt_disk_uuid: Uuid,
    pub gpt_part_uuid: Uuid,
    pub part_uuid: Uuid,
}

unsafe impl Send for File {}
unsafe impl Sync for File {}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File")
            .field("address", &self.as_ptr())
            .field("len", &self.len())
            .field("path", &self.path())
            .field("cmdline", &self.cmdline())
            .field("media_type", &self.media_type)
            .field("tftp_ip", &self.tftp_ip)
            .field("tftp_port", &self.tftp_port)
            .field("partition_index", &self.partition_index)
            .field("mbr_disk_id", &self.mbr_disk_id)
            .field("gpt_disk_uuid", &self.gpt_disk_uuid)
            .field("gpt_part_uuid", &self.gpt_part_uuid)
            .field("part_uuid", &self.part_uuid)
            .finish()
    }
}

impl File {
    /// Create a new `File`
    ///
    /// # Safety
    ///
    /// `ptr`, `path`, and `cmdline` (if present) must all be valid pointers.
    #[cfg(feature = "bootloader")]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        ptr: *mut u8,
        len: usize,
        path: *mut c_char,
        cmdline: Option<*mut c_char>,
        media_type: u32,
        tftp_ip: u32,
        tftp_port: u32,
        partition_index: u32,
        mbr_disk_id: u32,
        gpt_disk_uuid: Uuid,
        gpt_part_uuid: Uuid,
        part_uuid: Uuid,
    ) -> File {
        Self {
            revision: 0,
            address: ptr,
            size: len,
            path: LiminePtr::new_unchecked(path),
            cmdline: cmdline.map(|ptr| unsafe { LiminePtr::new_unchecked(ptr) }),
            media_type,
            unused: 0,
            tftp_ip,
            tftp_port,
            partition_index,
            mbr_disk_id,
            gpt_disk_uuid,
            gpt_part_uuid,
            part_uuid,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut u8 {
        self.address
    }

    /// Returns the length of the file data, in bytes
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn path(&self) -> Option<&str> {
        self.path.as_str().ok()
    }

    #[inline(always)]
    pub fn cmdline(&self) -> Option<&str> {
        self.cmdline.and_then(|ptr| ptr.as_str().ok())
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.address as _, self.size) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.address, self.size) }
    }
}

#[repr(C)]
pub struct Framebuffer {
    pub addr: *mut u8,
    pub width: u64,
    pub height: u64,
    pub stride: u64,
    pub bpp: u16,
    pub pixel_format: PixelFormat,
    pub edid_size: usize,
    pub edid: Option<NonNull<u8>>,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelFormat {
    pub memory_model: u8,
    pub r_mask_size: u8,
    pub r_mask_shift: u8,
    pub g_mask_size: u8,
    pub g_mask_shift: u8,
    pub b_mask_size: u8,
    pub b_mask_shift: u8,
    pub unused: [u8; 7],
}

/// Limine Response Pointer
///
/// A unique pointer to bootloader-provided data.
#[repr(transparent)]
struct ResponsePtr<T: ?Sized>(UnsafeCell<Option<NonNull<T>>>);

unsafe impl<T: ?Sized + Send> Send for ResponsePtr<T> {}
// SAFETY: Ditto.
unsafe impl<T: ?Sized + Sync> Sync for ResponsePtr<T> {}

impl<T> ResponsePtr<T> {
    #[inline(always)]
    pub const fn null() -> ResponsePtr<T> {
        Self(UnsafeCell::new(None))
    }

    #[inline(always)]
    pub fn get(&self) -> Option<&T> {
        // SAFETY: This assumes the data is valid if the pointer is non-null.
        // We have a `&self` so we can guarantee that there are no mutable
        // references to the data.
        unsafe { self.0.get().read_volatile().map(|ptr| ptr.as_ref()) }
    }

    #[inline(always)]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        // SAFETY: This assumes the data is valid if the pointer is non-null.
        // We have an `&mut self` so we can guarantee that there are no other
        // references to the data.
        unsafe { self.0.get().read_volatile().map(|mut ptr| ptr.as_mut()) }
    }
}

mod private {
    pub trait Sealed {}
}

pub trait Request: private::Sealed {
    const ID: RequestId;
    type Feature: Feature;
}

pub trait Feature: private::Sealed {
    type Request: Request;
}

macro_rules! declare_feature {
    (@field_or_default $e:expr) => { $e };
    (@field_or_default) => { Default::default() };

    (
        request:
            $(#[$request_meta:meta])*
            struct $request_name:ident: $request_id_0:literal, $request_id_1:literal {
                $(
                    $(#[$request_field_meta:meta])*
                    $request_field_vis:vis $request_field_name:ident: $request_field_type:ty =
                        |$b:ident| $($e:expr)?
                ),*
                $(,)?
            }

        response:
            $(#[$response_meta:meta])*
            struct $response_name:ident {
                $(
                    $(#[$response_field_meta:meta])*
                    $response_field_vis:vis $response_field_name:ident: $response_field_type:ty
                ),*$(,)?
            }
    ) => {

        #[repr(C)]
        #[doc = concat!("Request for the [`", stringify!($response_name), "`] feature")]
        $(#[$request_meta])*
        pub struct $request_name {
            id: $crate::RequestId,
            revision: usize,
            response: $crate::ResponsePtr<$response_name>,
            $(
                $(#[$request_field_meta])*
                $request_field_vis $request_field_name: $request_field_type
            ),*
        }

        impl $crate::private::Sealed for $request_name {}

        impl $crate::Request for $request_name {
            const ID: $crate::RequestId = $crate::RequestId::new([$request_id_0, $request_id_1]);
            type Feature = $response_name;
        }

        impl $request_name {
            #[doc = concat!("Create a new `", stringify!($request_name), "`")]
            pub const fn new($($b: $request_field_type),*) -> Self {
                Self {
                    id: Self::ID,
                    revision: 0,
                    response: $crate::ResponsePtr::null(),
                    $($request_field_name$(: $e)?),*
                }
            }

            /// Returns the [`RequestId`] of this request
            #[inline(always)]
            pub const fn id(&self) -> $crate::RequestId {
                self.id
            }

            #[inline(always)]
            pub const fn revision(&self) -> usize {
                self.revision
            }

            #[inline(always)]
            pub fn response(&self) -> Option<&$response_name> {
                self.response.get()
            }

            /// Set the response pointer
            ///
            /// This must only be called by the bootloader if it has properly handled
            /// the requested feature.
            ///
            /// # Safety
            ///
            /// The caller must guarantee that no other references to this request exist,
            /// as if the method took `&mut self`.
            pub unsafe fn set_response(&self, ptr: *mut $response_name) {
                self.response.0.get().write_volatile(Some(NonNull::new(ptr).unwrap()));
            }

            #[inline(always)]
            pub fn response_mut(&mut self) -> Option<&mut $response_name> {
                self.response.get_mut()
            }

            #[inline(always)]
            pub fn has_response(&self) -> bool {
                self.response().is_some()
            }
        }

        #[repr(C)]
        $(#[$response_meta])*
        pub struct $response_name {
            pub revision: usize,
            $(
                $(#[$response_field_meta])*
                $response_field_vis $response_field_name: $response_field_type
            ),*
        }

        impl private::Sealed for $response_name {}

        impl Feature for $response_name {
            type Request = $request_name;
        }

        impl $response_name {
            // pub const fn new($($response_field_name: $response_field_type),*) -> Self {
            //     Self {
            //         revision: 0,
            //         $($response_field_name),*
            //     }
            // }

            #[inline(always)]
            pub const fn revision(&self) -> usize {
                self.revision
            }
        }
    };
}

/*
 * Bootloader Information
 */

declare_feature! {
    request:
        struct BootloaderInfoRequest : 0xf55038d8e2a1202f, 0x279426fcf5f59740 {}

    response:
        struct BootloaderInfo {
            name: LiminePtr<c_char>,
            version: LiminePtr<c_char>,
        }
}

unsafe impl Send for BootloaderInfo {}
unsafe impl Sync for BootloaderInfo {}

impl BootloaderInfo {
    /// Create a new `BootloaderInfo` structure.
    ///
    /// # Safety
    ///
    /// Both `name` and `version` must be valid ASCII byte strings terminated with
    /// a NUL byte.
    #[cfg(feature = "bootloader")]
    pub unsafe fn new(name: *mut c_char, version: *mut c_char) -> BootloaderInfo {
        debug_assert!(!name.is_null());
        debug_assert!(!version.is_null());
        Self {
            revision: 0,
            name: LiminePtr::new_unchecked(name),
            version: LiminePtr::new_unchecked(version),
        }
    }

    /// Returns the bootloader's brand string
    ///
    /// # Panics
    ///
    /// This function will panic if the bootloader provided string is not valid UTF-8.
    pub fn brand(&self) -> &str {
        self.name.as_str().unwrap()
    }

    /// Returns the bootloader's version string
    ///
    /// # Panics
    ///
    /// This function will panic for the same reasons as [`brand()`].
    pub fn version(&self) -> &str {
        self.version.as_str().unwrap()
    }
}

/*
 * Stack Size
 */

declare_feature! {
    request:
        struct StackSizeRequest : 0x224ef0460a8e8926, 0xe1cb0fc25f46ea3d {
            pub stack_size: usize = |stack_size|,
        }

    response:
        struct StackSize {}
}

impl StackSize {
    #[cfg(feature = "bootloader")]
    pub const fn new() -> StackSize {
        Self { revision: 0 }
    }
}

/*
 * Higher-Half Direct Map (HHDM)
 */

declare_feature! {
    request:
        struct HhdmRequest : 0x48dcf1cb8ad2b852, 0x63984e959a98244b {}

    response:
        struct Hhdm {
            pub base: usize,
        }
}

impl Hhdm {
    #[cfg(feature = "bootloader")]
    pub const fn new(base: usize) -> Hhdm {
        Self { revision: 0, base }
    }
}

/*
 * Framebuffer
 */

declare_feature! {
    request:
        struct FramebufferRequest : 0x9d5827dcd881dd75, 0xa3148604f6fab11b {}

    response:
        struct Framebuffers {
            num_bufs: usize,
            framebuffers: ArrayPtr<Framebuffer>,
        }
}

unsafe impl Send for FramebufferRequest {}
unsafe impl Sync for FramebufferRequest {}

impl Framebuffers {
    pub fn framebuffers(&self) -> impl Iterator<Item = &Framebuffer> {
        self.framebuffers.make_iterator(self.num_bufs)
    }
}

/*
 * 5-level Paging
 */

declare_feature! {
    request:
        struct FiveLevelPagingRequest : 0x94469551da9b3192, 0xebe5e86db7382888 {}

    response:
        struct FiveLevelPaging {}
}

impl FiveLevelPaging {
    #[cfg(feature = "bootloader")]
    pub const fn new() -> FiveLevelPaging {
        Self { revision: 0 }
    }
}

/*
 * SMP (multiprocessor)
 */

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct SmpRequestFlags : u64 {
        #[cfg(target_arch = "x86_64")]
        const X2APIC = 0x1;
    }

    #[repr(transparent)]
    pub struct SmpFlags : u32 {
        #[cfg(target_arch = "x86_64")]
        const X2APIC = 0x1;
    }
}

declare_feature! {
    request:
        struct SmpRequest : 0x95a67b819a1b857e, 0xa0b61b723b6a73e0 {
            flags: SmpRequestFlags = |flags|,
        }

    response:
        struct Smp {
            pub flags: SmpFlags,
            #[cfg(target_arch = "x86_64")]
            pub bsp_lapic_id: u32,
            #[cfg(target_arch = "aarch64")]
            pub bsp_mpidr: usize,
            #[cfg(target_arch = "riscv64")]
            pub bsp_hartid: usize,
            num_cpus: usize,
            cpus: ArrayPtr<SmpInfo>,
        }
}

unsafe impl Send for Smp {}
unsafe impl Sync for Smp {}

impl Smp {
    /// Create a new `Smp` response
    ///
    /// # Safety
    ///
    /// `cpus` must be a valid pointer to an array of pointers, which themselves are valid
    /// pointers to an [`SmpInfo`].
    #[cfg(feature = "bootloader")]
    pub unsafe fn new(
        flags: SmpFlags,
        #[cfg(target_arch = "x86_64")] bsp_lapic_id: u32,
        #[cfg(target_arch = "aarch64")] bsp_mpidr: usize,
        #[cfg(target_arch = "riscv64")] bsp_hartid: usize,
        cpus: *mut *mut SmpInfo,
        len: usize,
    ) -> Smp {
        Self {
            revision: 0,
            flags,
            #[cfg(target_arch = "x86_64")]
            bsp_lapic_id,
            #[cfg(target_arch = "aarch64")]
            bsp_mpidr,
            #[cfg(target_arch = "riscv64")]
            bsp_hartid,
            num_cpus: len,
            cpus: ArrayPtr::new_unchecked(cpus.cast()),
        }
    }

    #[inline]
    pub fn cpus(&self) -> impl Iterator<Item = &SmpInfo> {
        self.cpus.make_iterator(self.num_cpus)
    }
}

#[repr(C)]
#[derive(Default)]
pub struct SmpInfo {
    /// ACPI Processor UID
    pub processor_id: u32,

    #[cfg(target_arch = "x86_64")]
    /// Local APIC ID
    pub lapic_id: u32,

    #[cfg(target_arch = "aarch64")]
    /// GIC CPU Interface Number
    pub gic_iface_no: usize,
    #[cfg(target_arch = "aarch64")]
    /// Processor MPIDR
    pub mpidr: usize,

    #[cfg(target_arch = "riscv64")]
    /// Hart ID
    pub hartid: usize,

    _reserved: u64,
    goto_addr: AtomicUsize,
    argument: UnsafeCell<usize>,
}

pub type SmpEntryPoint = unsafe extern "C" fn(&SmpInfo) -> !;

impl SmpInfo {
    #[cfg(feature = "bootloader")]
    pub const fn new(
        processor_id: u32,
        #[cfg(target_arch = "x86_64")] lapic_id: u32,
        #[cfg(target_arch = "aarch64")] gic_iface_no: usize,
        #[cfg(target_arch = "aarch64")] mpidr: usize,
        #[cfg(target_arch = "riscv64")] hartid: usize,
    ) -> SmpInfo {
        Self {
            processor_id,
            #[cfg(target_arch = "x86_64")]
            lapic_id,
            #[cfg(target_arch = "aarch64")]
            gic_iface_no,
            #[cfg(target_arch = "aarch64")]
            mpidr,
            #[cfg(target_arch = "riscv64")]
            hartid,
            _reserved: 0,
            goto_addr: AtomicUsize::new(0),
            argument: UnsafeCell::new(0),
        }
    }

    /// Start the CPU.
    ///
    /// The CPU will begin executing at `entry` with the same machine state at the BSP.
    ///
    /// # Safety
    ///
    /// This function must only be called once. Any subsequent calls to this function will
    /// overwrite the previously stored `arg`, potentially corrupting the AP's state.
    pub unsafe fn start(&self, entry: SmpEntryPoint, arg: usize) {
        self.argument.get().write_volatile(arg);
        self.goto_addr.store(entry as usize, Ordering::SeqCst);
    }

    pub fn argument(&self) -> usize {
        unsafe { self.argument.get().read() }
    }
}

/*
 * Memory Map
 */

declare_feature! {
    request:
        struct MemoryMapRequest : 0x67cf3d9d378a806f, 0xe304acdfc50c3c62 {}

    response:
        struct MemoryMap {
            len: usize,
            ptr: ArrayPtr<MemoryMapEntry>,
        }
}

unsafe impl Send for MemoryMap {}
unsafe impl Sync for MemoryMap {}

impl MemoryMap {
    /// Create a new `MemoryMap` response
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to an array of pointers, which themselves are valid
    /// pointers to a [`MemoryMapEntry`].
    #[cfg(feature = "bootloader")]
    pub unsafe fn new(ptr: *mut *mut MemoryMapEntry, len: usize) -> MemoryMap {
        Self {
            revision: 0,
            len,
            ptr: LiminePtr::new_unchecked(ptr.cast()),
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn entries(&self) -> impl Iterator<Item = &MemoryMapEntry> {
        self.ptr.make_iterator(self.len)
    }

    pub fn entries_mut(&mut self) -> impl Iterator<Item = &mut MemoryMapEntry> {
        self.ptr.make_iterator_mut(self.len)
    }

    pub fn usable_entries(&self) -> impl Iterator<Item = &MemoryMapEntry> {
        self.ptr
            .make_iterator(self.len)
            .filter(|entry| entry.kind() == MemoryKind::Usable)
    }

    pub fn usable_entries_mut(&mut self) -> impl Iterator<Item = &mut MemoryMapEntry> {
        self.ptr
            .make_iterator_mut(self.len)
            .filter(|entry| entry.kind() == MemoryKind::Usable)
    }

    pub fn steal_pages(&mut self, num_pages: usize) -> Option<usize> {
        self.entries_mut().find_map(|entry| {
            (entry.is_usable() && entry.size >= 4096 * num_pages).then(|| {
                entry.size -= 4096 * num_pages;
                entry.base + entry.size
            })
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MemoryMapEntry {
    pub base: usize,
    pub size: usize,
    kind: usize,
}

impl core::fmt::Debug for MemoryMapEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryMapEntry")
            .field("base", &self.base)
            .field("size", &self.size)
            .field("kind", &self.kind())
            .finish()
    }
}

impl MemoryMapEntry {
    pub const fn new(base: usize, size: usize, kind: MemoryKind) -> MemoryMapEntry {
        Self {
            base,
            size,
            kind: kind.to_usize(),
        }
    }

    pub fn kind(&self) -> MemoryKind {
        use MemoryKind::*;

        match self.kind {
            0 => Usable,
            1 => Reserved,
            2 => AcpiReclaimable,
            3 => AcpiNvs,
            4 => BadMemory,
            5 => BootloaderReclaimable,
            6 => KernelModules,
            7 => Framebuffer,
            8 => EfiRuntimeCode,
            9 => EfiRuntimeData,
            x => Unknown(x),
        }
    }

    pub fn is_usable(&self) -> bool {
        self.kind() == MemoryKind::Usable
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    BadMemory,
    BootloaderReclaimable,
    KernelModules,
    Framebuffer,
    EfiRuntimeCode,
    EfiRuntimeData,
    Unknown(usize),
}

impl MemoryKind {
    pub const fn from_usize(x: usize) -> MemoryKind {
        match x {
            0 => MemoryKind::Usable,
            1 => MemoryKind::Reserved,
            2 => MemoryKind::AcpiReclaimable,
            3 => MemoryKind::AcpiNvs,
            4 => MemoryKind::BadMemory,
            5 => MemoryKind::BootloaderReclaimable,
            6 => MemoryKind::KernelModules,
            7 => MemoryKind::Framebuffer,
            8 => MemoryKind::EfiRuntimeCode,
            9 => MemoryKind::EfiRuntimeData,
            _ => MemoryKind::Unknown(x),
        }
    }

    pub const fn to_usize(self) -> usize {
        match self {
            MemoryKind::Usable => 0,
            MemoryKind::Reserved => 1,
            MemoryKind::AcpiReclaimable => 2,
            MemoryKind::AcpiNvs => 3,
            MemoryKind::BadMemory => 4,
            MemoryKind::BootloaderReclaimable => 5,
            MemoryKind::KernelModules => 6,
            MemoryKind::Framebuffer => 7,
            MemoryKind::EfiRuntimeCode => 8,
            MemoryKind::EfiRuntimeData => 9,
            MemoryKind::Unknown(x) => x,
        }
    }
}

/*
 * Entry Point
 */

pub type EntryPointFn = unsafe extern "C" fn() -> !;

declare_feature! {
    request:
        struct EntryPointRequest : 0x13d86c035a1cd3e1, 0x2b0caa89d8f3026a {
            pub entry: EntryPointFn = |entry|,
        }

    response:
        struct EntryPoint {}
}

impl EntryPoint {
    #[cfg(feature = "bootloader")]
    pub const fn new() -> EntryPoint {
        Self { revision: 0 }
    }
}

/*
 * Kernel File
 */

declare_feature! {
    request:
        struct KernelFileRequest : 0xad97e90e83f1ed67, 0x31eb5d1c5ff23b69 {}

    response:
        struct KernelFile {
            file: *mut File,
        }
}

unsafe impl Send for KernelFile {}
unsafe impl Sync for KernelFile {}

impl KernelFile {
    /// Create a new `KernelFile` response
    ///
    /// # Safety
    ///
    /// `file` must be a valid pointer to a [`File`].
    #[cfg(feature = "bootloader")]
    pub unsafe fn new(file: *mut File) -> KernelFile {
        Self { revision: 0, file }
    }
}

impl core::ops::Deref for KernelFile {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.file }
    }
}

impl core::ops::DerefMut for KernelFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.file }
    }
}

/*
 * Modules
 */

declare_feature! {
    request:
        struct ModulesRequest : 0x3e7e279702be32af, 0xca1c4f3bd1280cee {}

    response:
        struct Modules {
            len: usize,
            data: ArrayPtr<File>,
        }
}

unsafe impl Send for Modules {}
unsafe impl Sync for Modules {}

impl Modules {
    /// Create a new `Modules` response
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer to an array of pointers, which themselves are valid
    /// pointers to a [`File`].
    #[cfg(feature = "bootloader")]
    pub unsafe fn new(ptr: *mut *mut File, len: usize) -> Modules {
        Self {
            revision: 0,
            len,
            data: ArrayPtr::new_unchecked(ptr.cast()),
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn modules(&self) -> impl Iterator<Item = &File> {
        self.data.make_iterator(self.len)
    }

    pub fn modules_mut(&mut self) -> impl Iterator<Item = &mut File> {
        self.data.make_iterator_mut(self.len)
    }

    pub fn find_module(&self, path: &str) -> Option<&File> {
        self.modules().find(|file| file.path() == Some(path))
    }

    pub fn find_module_mut(&mut self, path: &str) -> Option<&mut File> {
        self.modules_mut().find(|file| file.path() == Some(path))
    }
}

/*
 * Root System Description Pointer (RSDP)
 */

declare_feature! {
    request:
        struct RsdpRequest : 0xc5e77b6b397e7b43, 0x27637845accdcf3c {}

    response:
        struct Rsdp {
            pub rsdp_addr: *mut u8,
        }
}

// SAFETY: `Rsdp` does not access the contained pointer.
unsafe impl Send for Rsdp {}
// SAFETY: `Rsdp` does not access the contained pointer.
unsafe impl Sync for Rsdp {}

/*
 * System Management BIOS (SMBIOS)
 */

declare_feature! {
    request:
        struct SmbiosRequest : 0x9e9046f11e095391, 0xaa4a520fefbde5ee {}

    response:
        struct Smbios {
            /// Address of the 32-bit entry point
            entry32: *mut u8,
            /// Address of the 64-bit entry point
            entry64: *mut u8,
        }
}

// SAFETY: `Smbios` does not access the contained pointer.
unsafe impl Send for Smbios {}
// SAFETY: `Smbios` does not access the contained pointer.
unsafe impl Sync for Smbios {}

/*
 * EFI System Table
 */

declare_feature! {
    request:
        struct EfiSystemTableRequest : 0x5ceba5163eaaf6d6, 0x0a6981610cf65fcc {}

    response:
        struct EfiSystemTable {
            pub addr: *mut u8,
        }
}

// SAFETY: `EfiSystemTable` does not access the contained pointer.
unsafe impl Send for EfiSystemTable {}
// SAFETY: `EfiSystemTable` does not access the contained pointer.
unsafe impl Sync for EfiSystemTable {}

/*
 * Boot Time
 */

declare_feature! {
    request:
        struct BootTimeRequest : 0x502746e184c088aa, 0xfbc5ec83e6327893 {}

    response:
        /// Reports the system time on boot
        ///
        /// The availability of this features depends on the presence of an RTC in the system.
        struct BootTime {
            /// Time on boot, as a UNIX timestamp
            pub boot_time: i64,
        }
}

impl BootTime {
    #[cfg(feature = "bootloader")]
    pub const fn new(boot_time: i64) -> BootTime {
        Self {
            revision: 0,
            boot_time,
        }
    }
}

/*
 * Kernel Address
 */

declare_feature! {
    request:
        struct KernelAddressRequest : 0x71ba76863cc55f63, 0xb2644a48c516a487 {}

    response:
        /// Reports the virtual and physical base addresses of the kernel
        struct KernelAddress {
            pub phys: usize,
            pub virt: usize,
        }
}

impl KernelAddress {
    #[cfg(feature = "bootloader")]
    pub const fn new(phys: usize, virt: usize) -> KernelAddress {
        Self {
            revision: 0,
            phys,
            virt,
        }
    }
}

/*
 * Device Tree Blob
 */

declare_feature! {
    request:
        struct DtbRequest : 0xb40ddb48fb54bac7, 0x545081493f81ffb7 {}

    response:
        /// Device Tree Blob
        ///
        /// Reports the address of the Device Tree Blob (DTB) passed by firmware.
        ///
        /// # Note
        ///
        /// The information in the DTB's `/chosen` node may disagree with the information
        /// provide by other protocol features.
        struct Dtb {
            /// *Physical* address of the DTB
            pub dtb_ptr: *mut u8,
        }
}

// SAFETY: `Dtb` does not access the contained pointer.
unsafe impl Send for Dtb {}
// SAFETY: `Dtb` does not access the contained pointer.
unsafe impl Sync for Dtb {}

impl Dtb {
    #[cfg(feature = "bootloader")]
    pub const fn new(ptr: *mut u8) -> Dtb {
        Self {
            revision: 0,
            dtb_ptr: ptr,
        }
    }
}

/*
 * Paging Mode
 */

#[cfg(target_arch = "x86_64")]
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingMode {
    FourLevel = 0,
    FiveLevel,
}

#[cfg(target_arch = "riscv64")]
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingMode {
    Sv39 = 8,
    Sv48,
    Sv57,
}

declare_feature! {
    request:
        struct PagingModeRequest : 0x95c1a0edab0944cb, 0xa4e5cb3842f7488a {
            pub mode: PagingMode = |mode|,
            pub flags: PagingModeRequestFlags = |flags|,
        }

    response:
        struct PagingModeResponse {
            mode: usize,
            pub flags: PagingModeResponseFlags,
        }
}

impl PagingModeResponse {
    #[cfg(feature = "bootloader")]
    pub const fn new(mode: PagingMode, flags: PagingModeResponseFlags) -> PagingModeResponse {
        Self {
            revision: 0,
            mode: mode as usize,
            flags,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub const fn mode(&self) -> PagingMode {
        match self.mode {
            0 => PagingMode::FourLevel,
            1 => PagingMode::FiveLevel,
            _ => panic!("invalid paging mode"),
        }
    }

    #[cfg(target_arch = "riscv64")]
    pub const fn mode(&self) -> PagingMode {
        match self.mode {
            8 => PagingMode::Sv39,
            9 => PagingMode::Sv48,
            10 => PagingMode::Sv57,
            _ => panic!("invalid paging mode"),
        }
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct PagingModeRequestFlags : usize {}

    #[repr(transparent)]
    pub struct PagingModeResponseFlags : usize {}
}
