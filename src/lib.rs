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

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{
    cell::UnsafeCell,
    ffi::c_char,
    ptr::NonNull,
    sync::atomic::{AtomicPtr, Ordering},
};
#[cfg(feature = "alloc")]
use alloc:: {
    boxed::Box,
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
    #[inline(always)]
    pub const fn new(uniq: [u64; 2]) -> RequestId {
        Self([0xc7b1dd30df4c8b88, 0x0a82e883a194f07b, uniq[0], uniq[1]])
    }
}

/// A pointer to a resource provided by the bootloader
#[repr(transparent)]
pub struct LiminePtr<T: ?Sized>(NonNull<T>);

unsafe impl<T: ?Sized + Send> Send for LiminePtr<T> {}
unsafe impl<T: ?Sized + Sync> Sync for LiminePtr<T> {}

impl<T> LiminePtr<T> {
    pub fn new(ptr: *mut T) -> Option<LiminePtr<T>> {
        Some(Self(NonNull::new(ptr)?))
    }
}

impl<T: ?Sized> LiminePtr<T> {
    /// Create a new `LiminePtr` by leaking a [`Box`]
    #[cfg(feature = "alloc")]
    pub fn new_from_box(x: Box<T>) -> LiminePtr<T> {
        unsafe { Self(NonNull::new_unchecked(Box::leak(x) as *mut T)) }
    }

    /// Creates a new `LiminePtr`
    ///
    /// # Safety
    ///
    /// `ptr` must not be null
    pub unsafe fn new_unchecked(ptr: *mut T) -> LiminePtr<T> {
        Self(NonNull::new_unchecked(ptr))
    }

    /// Returns a shared reference to the value
    ///
    /// # Safety
    ///
    /// The same requirements as for [`NonNull::as_ref()`] apply.
    pub unsafe fn as_ref(&self) -> &T {
        self.0.as_ref()
    }

    /// Returns a unique reference to the value
    ///
    /// # Safety
    ///
    /// The same requirements as for [`NonNull::as_mut()`] apply.
    pub unsafe fn as_mut(&mut self) -> &mut T {
        self.0.as_mut()
    }
}

impl<T> core::ops::Deref for LiminePtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for LiminePtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <T as core::fmt::Debug>::fmt(self, f)
    }
}

impl LiminePtr<c_char> {
    pub fn as_str<'a>(&self) -> Result<&'a str, core::str::Utf8Error> {
        let ptr = self.0.as_ptr().cast::<u8>();
        let data = unsafe { core::slice::from_raw_parts(ptr, strlen(ptr)) };
        core::str::from_utf8(data)
    }
}

type ArrayPtr<T> = LiminePtr<LiminePtr<T>>;

impl<'a, T: 'a + ?Sized> ArrayPtr<T> {
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
#[derive(Debug)]
pub struct Uuid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

#[repr(C)]
#[derive(Debug)]
pub struct File {
    revision: usize,
    address: *mut u8,
    size: usize,
    path: LiminePtr<c_char>,
    cmdline: LiminePtr<c_char>,
    media_type: u32,
    unused: u32,
    tftp_ip: u32,
    tftp_port: u32,
    partition_index: u32,
    mbr_disk_id: u32,
    gpt_disk_uuid: Uuid,
    gpt_part_uuid: Uuid,
    part_uuid: Uuid,
}

unsafe impl Send for File {}

impl File {
    #[inline(always)]
    pub fn path(&self) -> &str {
        self.path.as_str().unwrap()
    }

    #[inline(always)]
    pub fn cmdline(&self) -> &str {
        self.cmdline.as_str().unwrap()
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.address as _, self.size) }
    }
}

#[repr(C)]
pub struct Framebuffer {
    addr: Option<NonNull<u8>>,
    width: u64,
    height: u64,
    stride: u64,
    bpp: u16,
    pixel_format: PixelFormat,
    edid_size: usize,
    edid: Option<NonNull<u8>>,
}

unsafe impl Send for Framebuffer {}

#[repr(C)]
pub struct PixelFormat {
    memory_model: u8,
    r_mask_size: u8,
    r_mask_shift: u8,
    g_mask_size: u8,
    g_mask_shift: u8,
    b_mask_size: u8,
    b_mask_shift: u8,
    unused: u8,
}

impl PixelFormat {
    #[inline(always)]
    pub const fn pixel(self, r: u8, g: u8, b: u8) -> u32 {
        let r = ((r as u32) & ((1 << self.r_mask_size) - 1)) << self.r_mask_shift;
        let g = ((g as u32) & ((1 << self.g_mask_size) - 1)) << self.g_mask_shift;
        let b = ((b as u32) & ((1 << self.b_mask_size) - 1)) << self.b_mask_shift;

        r | g | b
    }
}

/// Limine Response Pointer
///
/// An owning pointer to a response from the bootloader.
#[repr(transparent)]
struct ResponsePtr<T: ?Sized>(UnsafeCell<Option<NonNull<T>>>);

unsafe impl<T: ?Sized + Send> Send for ResponsePtr<T> {}
unsafe impl<T: ?Sized + Sync> Sync for ResponsePtr<T> {}

impl<T> ResponsePtr<T> {
    #[inline(always)]
    pub const fn null() -> ResponsePtr<T> {
        Self(UnsafeCell::new(None))
    }

    #[inline(always)]
    pub fn get(&self) -> Option<&T> {
        unsafe { self.0.get().read_volatile().map(|ptr| ptr.as_ref()) }
    }

    #[inline(always)]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        unsafe { self.0.get().read_volatile().map(|mut ptr| ptr.as_mut()) }
    }
}

macro_rules! declare_feature {
    (
        request:
            $(#[$request_meta:meta])*
            struct $request_name:ident: $request_id_0:literal, $request_id_1:literal {
                $($request_field_name:ident: $request_field_type:ty = ($b:ident) $($e:expr)?),*$(,)?
            }

        response:
            $(#[$response_meta:meta])*
            struct $response_name:ident {
                $($response_field_name:ident: $response_field_type:ty),*$(,)?
            }
    ) => {

        #[repr(C)]
        $(#[$request_meta])*
        pub struct $request_name {
            id: RequestId,
            revision: usize,
            response: ResponsePtr<$response_name>,
            $($request_field_name: $request_field_type),*
        }

        impl $request_name {
            pub const ID: RequestId = RequestId::new([$request_id_0, $request_id_1]);

            #[doc = concat!("Create a new `", stringify!($request_name), "`")]
            pub const fn new($($b: $request_field_type),*) -> Self {
                Self {
                    id: Self::ID,
                    revision: 0,
                    response: ResponsePtr::null(),
                    $($request_field_name$(: $e)?),*
                }
            }

            #[inline(always)]
            pub const fn id(&self) -> RequestId {
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

            pub unsafe fn set_response(&self, ptr: LiminePtr<$response_name>) {
                self.response.0.get().write(Some(ptr.0));
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
            revision: usize,
            $($response_field_name: $response_field_type),*
        }

        impl $response_name {
            pub const fn new($($response_field_name: $response_field_type),*) -> Self {
                Self {
                    revision: 0,
                    $($response_field_name),*
                }
            }

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

impl BootloaderInfo {
    pub fn brand(&self) -> &str {
        self.name.as_str().unwrap()
    }

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
            stack_size: usize = (stack_size),
        }

    response:
        struct StackSize {}
}

/*
 * Higher-Half Direct Map (HHDM)
 */

declare_feature! {
    request:
        struct HhdmRequest : 0x48dcf1cb8ad2b852, 0x63984e959a98244b {}

    response:
        struct Hhdm {
            base: usize,
        }
}

impl Hhdm {
    pub const fn base(&self) -> usize {
        self.base
    }
}

/*
 * Terminal
 */

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

impl Framebuffers {
    pub fn framebuffers(&self) -> impl Iterator<Item = &Framebuffer> {
        self.framebuffers.make_iterator(self.num_bufs)
    }
}

/*
 * 5-level Paging
 */

/*
 * SMP (multiprocessor)
 */

declare_feature! {
    request:
        struct SmpRequest : 0x95a67b819a1b857e, 0xa0b61b723b6a73e0 {
            flags: SmpRequestFlags = (flags),
        }

    response:
        struct Smp {
            flags: u32,
            bsp_lapic_id: u32,
            num_cpus: usize,
            // cpus: *const *const SmpInfo,
            cpus: ArrayPtr<SmpInfo>,
        }
}

unsafe impl Send for SmpRequest {}
unsafe impl Send for Smp {}

#[repr(C)]
#[derive(Debug)]
pub struct SmpInfo {
    processor_id: u32,
    lapic_id: u32,
    reserved: u64,
    /// AP startup address
    ///
    /// An atomic write to this field will break the corresponding AP from its
    /// wait-loop, causing it to jump to the address written.
    goto_addr: AtomicPtr<extern "C" fn() -> !>,
    argument: UnsafeCell<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmpStartupError;

impl SmpInfo {
    pub fn new(processor_id: u32, lapic_id: u32, reserved: u64) -> SmpInfo {
        Self {
            processor_id,
            lapic_id,
            reserved,
            goto_addr: AtomicPtr::new(core::ptr::null_mut()),
            argument: UnsafeCell::new(0),
        }
    }

    /// Returns the LAPIC ID for this processor
    #[inline(always)]
    pub const fn lapic_id(&self) -> u32 {
        self.lapic_id
    }

    /// Start up the processor described by this entry.
    #[inline]
    pub fn start(&self, f: extern "C" fn(&SmpInfo) -> !, arg: usize) -> Result<(), SmpStartupError> {
        if !self.goto_addr.load(Ordering::SeqCst).is_null() {
            return Err(SmpStartupError);
        }

        unsafe { self.argument.get().write_volatile(arg) };
        self.goto_addr.store(f as _, Ordering::SeqCst);

        Ok(())
    }
}

impl Smp {
    #[inline]
    pub fn flags(&self) -> SmpFlags {
        unsafe { SmpFlags::from_bits_unchecked(self.flags) }
    }

    #[inline(always)]
    pub const fn bsp_lapic_id(&self) -> u32 {
        self.bsp_lapic_id
    }

    #[inline(always)]
    pub const fn num_cpus(&self) -> usize {
        self.num_cpus
    }

    #[inline]
    pub fn cpus(&self) -> impl Iterator<Item = &SmpInfo> {
        self.cpus.make_iterator(self.num_cpus)
        // unsafe { core::slice::from_raw_parts(self.cpus as *const &SmpInfo, self.num_cpus) }
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct SmpRequestFlags : u64 {
        const X2APIC = 0x1;
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct SmpFlags : u32 {
        const X2APIC = 0x1;
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

impl MemoryMap {
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

    pub fn steal_pages(&mut self, num_pages: usize) -> Option<usize> {
        self.entries_mut().find_map(|entry| {
            // Usable regions are guaranteed to have page aligned base and size.
            if entry.is_usable() && entry.size() >= 4096 * num_pages {
                entry.size -= 4096 * num_pages;
                Some(entry.base() + entry.size())
            } else {
                None
            }
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MemoryMapEntry {
    pub base: usize,
    pub size: usize,
    pub kind: usize,
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

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn size(&self) -> usize {
        self.size
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

/*
 * Kernel File
 */

declare_feature! {
    request:
        struct KernelFileRequest : 0xad97e90e83f1ed67, 0x31eb5d1c5ff23b69 {}

    response:
        struct KernelFile {
            file: LiminePtr<File>,
        }
}

impl core::ops::Deref for KernelFile {
    type Target = LiminePtr<File>;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl core::ops::DerefMut for KernelFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
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

impl Modules {
    pub fn modules(&self) -> impl Iterator<Item = &File> {
        self.data.make_iterator(self.len)
    }

    pub fn find_module(&self, path: &str) -> Option<&File> {
        self.modules().find(|file| file.path() == path)
    }
}

/*
 * Root System Description Pointer (RSDP)
 */

/*
 * System Management BIOS (SMBIOS)
 */

/*
 * EFI System Table
 */

/*
 * Boot Time
 */

/*
 * Kernel Address
 */

declare_feature! {
    request:
        /// Requests the virtual and physical base addresses of the kernel
        struct KernelAddressRequest : 0x71ba76863cc55f63, 0xb2644a48c516a487 {}

    response:
        /// Reports the virtual and physical base addresses of the kernel
        struct KernelAddress {
            physical_base: usize,
            virtual_base: usize,
        }
}

impl KernelAddress {
    /// Returns the virtual base address of the loaded kernel image
    pub const fn virt_address(&self) -> usize {
        self.virtual_base
    }

    /// Returns the physical base address of the loaded kernel image
    pub const fn phys_address(&self) -> usize {
        self.physical_base
    }
}
