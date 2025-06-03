@extends('layouts.admin.app')

@section('title', translate('Update Menu'))

@section('content')
    <div class="content container-fluid">
        <h2 class="h1 mb-4">{{ translate('Update Menu') }}</h2>

        <div class="card">
            <div class="card-body">
                <form action="{{ route('admin.menu.menu.update', $menu->id) }}" method="POST" enctype="multipart/form-data">
                    @csrf
                    @method('PUT')
                    <div class="mb-3">
                        <label class="form-label">{{ translate('Menu Image') }}</label>
                        <br>
                        <input type="file" name="image" class="form-control">
                        <img src="{{ asset('storage/app/public/' . $menu->image) }}" width="80" alt="menu">
                    </div>
                    <br>
                    <div class="text-end">
                        <button type="submit" class="btn btn-primary">{{ translate('Save Changes') }}</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
@endsection